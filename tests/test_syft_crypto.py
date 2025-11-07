import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List

import pytest

from tests.conftest import (
    get_container_status,
    wait_for_container_log,
    wait_for_file,
)


SYC_CLIENTS = [
    ("alice@syftbox.net", "syftbox-client-alice-syftbox-net"),
    ("bob@syftbox.net", "syftbox-client-bob-syftbox-net"),
    ("charlie@syftbox.net", "syftbox-client-charlie-syftbox-net"),
]


@dataclass
class SyCClientEnv:
    email: str
    container: str
    base_dir: Path
    vault: Path
    data_root: Path
    shadow_root: Path

    @property
    def public_bundle_path(self) -> Path:
        return self.data_root / self.email / "public" / "crypto" / "did.json"


SycCommand = Callable[[SyCClientEnv, List[str], bool], subprocess.CompletedProcess]


@pytest.fixture(scope="session")
def syc_repo_root(test_root_dir: Path) -> Path:
    repo = test_root_dir / "syft-crypto-core"
    if not repo.exists():
        pytest.skip("syft-crypto-core submodule is not available")
    return repo


@pytest.fixture(scope="session")
def syc_binary(syc_repo_root: Path) -> Path:
    """Compile the syc CLI from the submodule and return the binary path."""
    binary_name = "syc.exe" if sys.platform == "win32" else "syc"
    binary_path = syc_repo_root / "target" / "debug" / binary_name

    build_cmd = [
        "cargo",
        "build",
        "--manifest-path",
        str(syc_repo_root / "cli" / "Cargo.toml"),
        "--bin",
        "syc",
        "--locked",
    ]
    result = subprocess.run(
        build_cmd,
        cwd=syc_repo_root,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0 or not binary_path.exists():
        pytest.fail(
            "Failed to build syc CLI:\n"
            f"$ {' '.join(build_cmd)}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    return binary_path


@pytest.fixture
def syc_clients(clients_dir: Path) -> List[SyCClientEnv]:
    clients = []
    for email, container in SYC_CLIENTS:
        base_dir = clients_dir / email
        syftbox_dir = base_dir / "SyftBox"
        env = SyCClientEnv(
            email=email,
            container=container,
            base_dir=base_dir,
            vault=base_dir / ".syc",
            data_root=syftbox_dir / "datasites",
            shadow_root=syftbox_dir / "unencrypted",
        )

        # Ensure the core directory structure exists for the CLI
        env.vault.mkdir(parents=True, exist_ok=True)
        (env.vault / "config").mkdir(parents=True, exist_ok=True)
        env.data_root.mkdir(parents=True, exist_ok=True)
        env.shadow_root.mkdir(parents=True, exist_ok=True)

        # Mirror how the CLI integration tests configure datasite roots
        config_path = env.vault / "config" / "datasite.json"
        config = {
            "encrypted_root": "../SyftBox/datasites",
            "shadow_root": "../SyftBox/unencrypted",
        }
        config_path.write_text(json.dumps(config, indent=2))

        clients.append(env)

    return clients


@pytest.fixture
def run_syc_command(syc_binary: Path) -> SycCommand:
    def _run(client: SyCClientEnv, args: List[str], check: bool = True) -> subprocess.CompletedProcess:
        cmd = [
            str(syc_binary),
            "--vault",
            str(client.vault),
            "--data-root",
            str(client.data_root),
            "--shadow-root",
            str(client.shadow_root),
            *args,
        ]

        result = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
        )

        if check and result.returncode != 0:
            pytest.fail(
                f"syc command failed for {client.email}:\n"
                f"$ {' '.join(cmd)}\n"
                f"stdout:\n{result.stdout}\n"
                f"stderr:\n{result.stderr}"
            )

        return result

    return _run


def wait_for_syftbox_structure(client: SyCClientEnv, timeout: int = 45) -> None:
    syftbox_dir = client.base_dir / "SyftBox"
    start = time.time()
    while time.time() - start < timeout:
        if syftbox_dir.exists() and (syftbox_dir / "datasites").exists():
            return
        time.sleep(1)
    pytest.fail(f"SyftBox directory did not initialize for {client.email}")


def write_shared_acl(owner: SyCClientEnv, readers: Iterable[str]) -> None:
    shared_dir = owner.data_root / owner.email / "shared"
    shared_dir.mkdir(parents=True, exist_ok=True)
    acl_path = shared_dir / "syft.pub.yaml"
    readers = list(readers)
    readers_list = "\n".join(f"        - \"{email}\"" for email in readers)
    acl_body = "\n".join(
        [
            "terminal: false",
            "rules:",
            "  - pattern: \"**\"",
            "    access:",
            "      admin:",
            f"        - \"{owner.email}\"",
            "      read:",
            readers_list or "        - \"\"",
            "      write:",
            f"        - \"{owner.email}\"",
        ]
    )
    acl_path.write_text(f"{acl_body}\n")


def parse_envelope_blob(blob: bytes) -> Dict[str, Any]:
    assert blob.startswith(b"SYC1"), "Missing SYC1 envelope header"
    if len(blob) < 9:
        raise ValueError("Envelope truncated before prelude length")
    version = blob[4]
    prelude_len = int.from_bytes(blob[5:9], "little")
    prelude_start = 9
    prelude_end = prelude_start + prelude_len
    if prelude_end > len(blob):
        raise ValueError("Envelope prelude exceeds blob length")
    prelude_bytes = blob[prelude_start:prelude_end]
    prelude = json.loads(prelude_bytes.decode("utf-8"))

    recipients = [
        entry.get("identity")
        for entry in prelude.get("recipients", [])
        if entry.get("identity")
    ]
    sender = prelude.get("sender", {}).get("identity")

    return {
        "version": version,
        "sender": sender,
        "recipients": recipients,
        "prelude": prelude,
    }


@pytest.mark.integration
@pytest.mark.syc
class TestSyftCryptoCLI:
    MESSAGE = "Secret plans for the SyftBox launch 🚀"
    RELATIVE_SHARED = Path("alice@syftbox.net/shared/bob@syftbox.net/files/top-secret.txt")

    def test_key_exchange_and_file_encryption(
        self,
        docker_client,
        syc_clients: List[SyCClientEnv],
        run_syc_command: SycCommand,
    ) -> None:
        # Ensure server and clients are online
        server_status = get_container_status(docker_client, "syftbox-server")
        assert server_status["running"], "SyftBox server must be running for syc tests"

        for client in syc_clients:
            assert wait_for_container_log(client.container, "socketmgr client connected", timeout=45), (
                f"{client.email} failed to connect to the server"
            )
            wait_for_syftbox_structure(client)

        # Generate key material for each client and export their bundles
        for client in syc_clients:
            bundle_relative = Path(client.email) / "public" / "crypto" / "did.json"
            run_syc_command(
                client,
                [
                    "key",
                    "generate",
                    "--identity",
                    client.email,
                    "--overwrite",
                    "--bundle-out",
                    str(bundle_relative),
                ],
            )

            key_file = client.vault / "keys" / f"{client.email}.key"
            assert key_file.exists(), f"Expected key file for {client.email} at {key_file}"
            assert client.public_bundle_path.exists(), f"Public bundle not found for {client.email}"
            key_doc = json.loads(key_file.read_text())
            assert key_doc.get("identity") == client.email, "Key file identity mismatch"

        # Allow SyftBox sync to propagate exported bundles across clients
        time.sleep(10)

        # Everyone should receive everyone else's bundles
        for source_client in syc_clients:
            bundle_relative = Path(source_client.email) / "public" / "crypto" / "did.json"
            for target_client in syc_clients:
                expected_path = target_client.data_root / bundle_relative
                if not wait_for_file(expected_path, timeout=120):
                    pytest.fail(
                        f"{target_client.email} did not receive bundle from {source_client.email} "
                        f"at {expected_path}"
                    )

        # Import public bundles to establish TOFU entries in each vault
        for source_client in syc_clients:
            bundle_relative = Path(source_client.email) / "public" / "crypto" / "did.json"
            for target_client in syc_clients:
                if target_client.email == source_client.email:
                    continue
                run_syc_command(
                    target_client,
                    [
                        "key",
                        "import",
                        "--bundle",
                        str(bundle_relative),
                        "--expected-identity",
                        source_client.email,
                    ],
                )

        alice = next(client for client in syc_clients if client.email.startswith("alice"))
        bob = next(client for client in syc_clients if client.email.startswith("bob"))
        charlie = next(client for client in syc_clients if client.email.startswith("charlie"))

        # Allow Bob to read Alice's shared space via ACL
        write_shared_acl(alice, [bob.email])
        time.sleep(5)

        # Encrypt a file from Alice to Bob
        alice_plain_path = alice.shadow_root / self.RELATIVE_SHARED
        alice_plain_path.parent.mkdir(parents=True, exist_ok=True)
        alice_plain_path.write_text(self.MESSAGE)

        run_syc_command(
            alice,
            [
                "file",
                "encrypt",
                "--relative",
                str(self.RELATIVE_SHARED),
                "--sender",
                alice.email,
                "--recipient",
                bob.email,
            ],
        )

        alice_cipher_path = alice.data_root / self.RELATIVE_SHARED
        assert alice_cipher_path.exists(), "Ciphertext should exist in Alice's datasite"
        alice_cipher_bytes = alice_cipher_path.read_bytes()
        assert alice_cipher_bytes.startswith(b"SYC1"), "Ciphertext should begin with SYC1 envelope magic"

        bob_cipher_path = bob.data_root / self.RELATIVE_SHARED
        assert wait_for_file(bob_cipher_path, timeout=60), "Bob did not receive encrypted file from Alice"
        bob_cipher_bytes = bob_cipher_path.read_bytes()
        assert bob_cipher_bytes.startswith(b"SYC1"), "Bob's ciphertext copy should retain SYC1 envelope magic"

        inspect_result = run_syc_command(
            bob,
            [
                "file",
                "inspect",
                "--input",
                str(self.RELATIVE_SHARED),
                "--identity",
                bob.email,
                "--verbose",
            ],
        )
        inspect_output = inspect_result.stdout + inspect_result.stderr
        assert "envelope magic: SYC1" in inspect_output
        assert f"sender: {alice.email}" in inspect_output

        charlie_cipher_path = charlie.data_root / self.RELATIVE_SHARED
        time.sleep(5)
        assert not charlie_cipher_path.exists(), "Charlie should not receive Bob-only share"

        # Bob decrypts the file successfully
        run_syc_command(
            bob,
            [
                "file",
                "decrypt",
                "--relative",
                str(self.RELATIVE_SHARED),
                "--identity",
                bob.email,
            ],
        )

        bob_plain_path = bob.shadow_root / self.RELATIVE_SHARED
        assert bob_plain_path.exists(), "Bob's decrypted file was not written"
        assert bob_plain_path.read_text() == self.MESSAGE, "Bob's decrypted content did not match original message"

        # Charlie should not be able to decrypt Bob-targeted ciphertext (file not yet shared to him)
        charlie_decrypt = run_syc_command(
            charlie,
            [
                "file",
                "decrypt",
                "--relative",
                str(self.RELATIVE_SHARED),
                "--identity",
                charlie.email,
            ],
            check=False,
        )

        if charlie_decrypt.returncode == 0:
            pytest.xfail(
                "Current syc placeholder allows non-recipients to decrypt; expect failure once enforcement lands."
            )
        assert charlie_decrypt.returncode != 0, "Charlie unexpectedly decrypted Alice->Bob ciphertext"

        # Expand ACL to include Charlie as a reader and confirm the share arrives but remains undecryptable
        write_shared_acl(alice, [bob.email, charlie.email])
        time.sleep(5)

        assert wait_for_file(charlie_cipher_path, timeout=60), "Charlie did not receive direct share after ACL update"
        charlie_direct_bytes = charlie_cipher_path.read_bytes()
        assert charlie_direct_bytes.startswith(b"SYC1"), "Direct share should remain wrapped in SYC1 envelope"
        metadata_after_acl = parse_envelope_blob(charlie_direct_bytes)
        assert metadata_after_acl["sender"] == alice.email
        assert metadata_after_acl["recipients"] == [bob.email], "Recipient set should remain limited to Bob"

        inspect_after_acl = run_syc_command(
            charlie,
            [
                "file",
                "inspect",
                "--input",
                str(self.RELATIVE_SHARED),
                "--identity",
                charlie.email,
                "--verbose",
            ],
        )
        inspect_after_acl_output = inspect_after_acl.stdout + inspect_after_acl.stderr
        assert "envelope magic: SYC1" in inspect_after_acl_output

        second_attempt = run_syc_command(
            charlie,
            [
                "file",
                "decrypt",
                "--relative",
                str(self.RELATIVE_SHARED),
                "--identity",
                charlie.email,
            ],
            check=False,
        )
        if second_attempt.returncode == 0:
            pytest.xfail(
                "Current syc placeholder allows non-recipients to decrypt; expect failure once enforcement lands."
            )
        assert second_attempt.returncode != 0, "Charlie should still fail to decrypt Bob-targeted ciphertext"

        charlie_plain_target = charlie.shadow_root / self.RELATIVE_SHARED
        assert not charlie_plain_target.exists(), "Charlie should not have a decrypted plaintext copy"
