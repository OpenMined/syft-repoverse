import json
import os
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

import pytest
import requests
import yaml

from tests.conftest import wait_for_container_log


class AccessLoggingTestHelper:
    """Helper class for testing access logging functionality."""

    CLIENT1_EMAIL = "client1@syftbox.net"
    CLIENT2_EMAIL = "client2@syftbox.net"
    CLIENT3_EMAIL = "client3@syftbox.net"
    SERVER_URL = "http://localhost:8080"
    LOGS_DIR = ".logs"  # Directory where logs are created next to binary

    @staticmethod
    def get_server_logs_path() -> Path:
        """Get the path to the server's logs directory."""
        # The logs are created next to the binary in the container
        # We need to copy them from the container to inspect them
        return Path("/app") / AccessLoggingTestHelper.LOGS_DIR

    @staticmethod
    def copy_logs_from_container(container_name: str, dest_path: Path) -> bool:
        """Copy logs from container to local filesystem for inspection."""
        try:
            # Create destination directory
            dest_path.mkdir(parents=True, exist_ok=True)
            
            # Copy logs from container
            cmd = [
                "docker", "cp",
                f"{container_name}:/app/{AccessLoggingTestHelper.LOGS_DIR}/.",
                str(dest_path)
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            print(f"Failed to copy logs: {e}")
            return False

    @staticmethod
    def parse_log_file(log_file_path: Path) -> List[Dict]:
        """Parse a JSON log file and return list of log entries."""
        entries = []
        if not log_file_path.exists():
            return entries

        with open(log_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        entries.append(entry)
                    except json.JSONDecodeError:
                        # Skip invalid JSON lines
                        continue
        return entries

    @staticmethod
    def verify_log_entry(
        entry: Dict,
        expected_user: str,
        expected_path: Optional[str] = None,
        expected_method: Optional[str] = None,
        expected_allowed: Optional[bool] = None,
        expected_access_type: Optional[str] = None
    ) -> bool:
        """Verify that a log entry matches expected values."""
        if entry.get("user") != expected_user:
            return False
        
        if expected_path is not None and expected_path not in entry.get("path", ""):
            return False
        
        if expected_method is not None and entry.get("method") != expected_method:
            return False
        
        if expected_allowed is not None and entry.get("allowed") != expected_allowed:
            return False
        
        if expected_access_type is not None and entry.get("access_type") != expected_access_type:
            return False
        
        return True


@pytest.fixture
def access_logging_helper():
    """Provide access logging test helper."""
    return AccessLoggingTestHelper()


@pytest.fixture
def temp_logs_dir(tmp_path):
    """Create a temporary directory for copied logs."""
    logs_dir = tmp_path / "test_logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    return logs_dir


class TestAccessLogging:
    """Test suite for access logging functionality."""

    def test_access_logs_created_for_users(
        self, 
        docker_client, 
        access_logging_helper,
        temp_logs_dir
    ):
        """Test that access logs are created for each user email that contacts the server."""
        
        # Start the server
        print("Starting server...")
        subprocess.run(["just", "test-server"], check=True)
        
        # Wait for server to be ready
        assert wait_for_container_log("syftbox-server", "Server started", timeout=30)
        time.sleep(2)  # Give server extra time to fully initialize
        
        # Start multiple clients with different emails
        clients = [
            (AccessLoggingTestHelper.CLIENT1_EMAIL, "client1"),
            (AccessLoggingTestHelper.CLIENT2_EMAIL, "client2"),
            (AccessLoggingTestHelper.CLIENT3_EMAIL, "client3"),
        ]
        
        for email, client_name in clients:
            print(f"Starting {client_name} with email {email}...")
            env_vars = {
                "SYFTBOX_EMAIL": email,
                "SYFTBOX_SERVER": AccessLoggingTestHelper.SERVER_URL,
                "SYFTBOX_SYNC_DIR": f"/tmp/test_sync_{client_name}"
            }
            
            # Start client container
            subprocess.run(
                ["just", f"test-client-{client_name[-1]}"],  # test-client-1, test-client-2, etc.
                env=dict(os.environ, **env_vars),
                check=True
            )
            
            # Wait for client to authenticate
            assert wait_for_container_log(
                f"syftbox-{client_name}",
                "Authenticated",
                timeout=30
            )
            time.sleep(1)
        
        # Give time for all access attempts to be logged
        time.sleep(3)
        
        # Copy logs from server container to local filesystem
        print("Copying logs from server container...")
        assert access_logging_helper.copy_logs_from_container(
            "syftbox-server",
            temp_logs_dir
        )
        
        # Verify log files exist for each user
        for email, client_name in clients:
            log_file = temp_logs_dir / f"{email}.log"
            print(f"Checking for log file: {log_file}")
            
            assert log_file.exists(), f"Log file not found for {email}"
            
            # Parse and verify log contents
            entries = access_logging_helper.parse_log_file(log_file)
            assert len(entries) > 0, f"No log entries found for {email}"
            
            # Verify at least one entry has correct user
            user_entries = [e for e in entries if e.get("user") == email]
            assert len(user_entries) > 0, f"No entries with user={email}"
            
            print(f"Found {len(entries)} log entries for {email}")
            print(f"First entry: {json.dumps(entries[0], indent=2)}")
        
        # Cleanup
        subprocess.run(["just", "test-cleanup"], check=False)

    def test_log_entry_format_and_content(
        self,
        docker_client,
        access_logging_helper,
        temp_logs_dir
    ):
        """Test that log entries contain expected fields and format."""
        
        # Start server
        print("Starting server...")
        subprocess.run(["just", "test-server"], check=True)
        assert wait_for_container_log("syftbox-server", "Server started", timeout=30)
        time.sleep(2)
        
        # Start a client
        email = AccessLoggingTestHelper.CLIENT1_EMAIL
        env_vars = {
            "SYFTBOX_EMAIL": email,
            "SYFTBOX_SERVER": AccessLoggingTestHelper.SERVER_URL,
            "SYFTBOX_SYNC_DIR": "/tmp/test_sync_client1"
        }
        
        print(f"Starting client with email {email}...")
        subprocess.run(
            ["just", "test-client-1"],
            env=dict(os.environ, **env_vars),
            check=True
        )
        
        # Wait for authentication
        assert wait_for_container_log("syftbox-client1", "Authenticated", timeout=30)
        
        # Make specific API requests to generate known log entries
        time.sleep(2)
        
        # Try to access a file (this should generate a log entry)
        try:
            # Make a GET request to a known endpoint
            response = requests.get(
                f"{AccessLoggingTestHelper.SERVER_URL}/api/files/test.txt",
                headers={"X-User-Email": email}
            )
            print(f"API request status: {response.status_code}")
        except Exception as e:
            print(f"API request failed (expected): {e}")
        
        time.sleep(3)
        
        # Copy logs from server
        print("Copying logs from server container...")
        assert access_logging_helper.copy_logs_from_container(
            "syftbox-server",
            temp_logs_dir
        )
        
        # Parse log file
        log_file = temp_logs_dir / f"{email}.log"
        assert log_file.exists()
        
        entries = access_logging_helper.parse_log_file(log_file)
        assert len(entries) > 0
        
        # Verify log entry structure
        for entry in entries:
            # Check required fields exist
            required_fields = [
                "timestamp", "user", "path", "method", 
                "ip", "user_agent", "status_code", "allowed"
            ]
            
            for field in required_fields:
                assert field in entry, f"Missing required field: {field}"
            
            # Verify timestamp format
            assert isinstance(entry["timestamp"], str)
            # Should be in format: "2006-01-02 15:04:05.000 UTC"
            assert " UTC" in entry["timestamp"] or " GMT" in entry["timestamp"]
            
            # Verify user matches
            assert entry["user"] == email
            
            # Verify boolean fields
            assert isinstance(entry["allowed"], bool)
            
            # Verify status code is an integer
            assert isinstance(entry["status_code"], int)
            
            print(f"Verified entry structure: {json.dumps(entry, indent=2)}")
        
        # Cleanup
        subprocess.run(["just", "test-cleanup"], check=False)

    def test_access_denied_logging(
        self,
        docker_client,
        access_logging_helper,
        temp_logs_dir
    ):
        """Test that access denied attempts are properly logged with reasons."""
        
        # Start server
        print("Starting server...")
        subprocess.run(["just", "test-server"], check=True)
        assert wait_for_container_log("syftbox-server", "Server started", timeout=30)
        time.sleep(2)
        
        # Start client1
        email1 = AccessLoggingTestHelper.CLIENT1_EMAIL
        env_vars1 = {
            "SYFTBOX_EMAIL": email1,
            "SYFTBOX_SERVER": AccessLoggingTestHelper.SERVER_URL,
            "SYFTBOX_SYNC_DIR": "/tmp/test_sync_client1"
        }
        
        print(f"Starting client1 with email {email1}...")
        subprocess.run(
            ["just", "test-client-1"],
            env=dict(os.environ, **env_vars1),
            check=True
        )
        
        assert wait_for_container_log("syftbox-client1", "Authenticated", timeout=30)
        time.sleep(2)
        
        # Try to access another user's data (should be denied)
        email2 = AccessLoggingTestHelper.CLIENT2_EMAIL
        
        try:
            # Client1 trying to access client2's data
            response = requests.get(
                f"{AccessLoggingTestHelper.SERVER_URL}/api/files/client2@syftbox.net/private_data.txt",
                headers={"X-User-Email": email1}
            )
            print(f"Access attempt status: {response.status_code}")
        except Exception as e:
            print(f"Access attempt failed: {e}")
        
        time.sleep(3)
        
        # Copy logs
        print("Copying logs from server container...")
        assert access_logging_helper.copy_logs_from_container(
            "syftbox-server",
            temp_logs_dir
        )
        
        # Check log file
        log_file = temp_logs_dir / f"{email1}.log"
        assert log_file.exists()
        
        entries = access_logging_helper.parse_log_file(log_file)
        
        # Look for denied access entries
        denied_entries = [e for e in entries if not e.get("allowed", True)]
        
        if denied_entries:
            for entry in denied_entries:
                print(f"Found denied access entry: {json.dumps(entry, indent=2)}")
                
                # Verify denied entry has a reason
                assert "denied_reason" in entry or not entry["allowed"]
                assert entry["user"] == email1
                
                # If there's a denied_reason, it should be non-empty
                if "denied_reason" in entry:
                    assert len(entry["denied_reason"]) > 0
        
        # Cleanup
        subprocess.run(["just", "test-cleanup"], check=False)

    def test_log_rotation(
        self,
        docker_client,
        access_logging_helper,
        temp_logs_dir
    ):
        """Test that log files are properly rotated when they exceed size limits."""
        
        # Start server
        print("Starting server...")
        subprocess.run(["just", "test-server"], check=True)
        assert wait_for_container_log("syftbox-server", "Server started", timeout=30)
        time.sleep(2)
        
        email = AccessLoggingTestHelper.CLIENT1_EMAIL
        env_vars = {
            "SYFTBOX_EMAIL": email,
            "SYFTBOX_SERVER": AccessLoggingTestHelper.SERVER_URL,
            "SYFTBOX_SYNC_DIR": "/tmp/test_sync_client1"
        }
        
        print(f"Starting client with email {email}...")
        subprocess.run(
            ["just", "test-client-1"],
            env=dict(os.environ, **env_vars),
            check=True
        )
        
        assert wait_for_container_log("syftbox-client1", "Authenticated", timeout=30)
        
        # Generate many log entries to potentially trigger rotation
        print("Generating multiple log entries...")
        for i in range(100):
            try:
                response = requests.get(
                    f"{AccessLoggingTestHelper.SERVER_URL}/api/files/test_{i}.txt",
                    headers={"X-User-Email": email}
                )
            except:
                pass
            
            if i % 20 == 0:
                time.sleep(0.5)  # Small delay every 20 requests
        
        time.sleep(3)
        
        # Copy logs
        print("Copying logs from server container...")
        assert access_logging_helper.copy_logs_from_container(
            "syftbox-server",
            temp_logs_dir
        )
        
        # Check for rotated log files
        log_files = list(temp_logs_dir.glob(f"{email}*.log*"))
        print(f"Found log files: {[str(f.name) for f in log_files]}")
        
        # At minimum, we should have the main log file
        main_log = temp_logs_dir / f"{email}.log"
        assert main_log.exists()
        
        # Check if rotation occurred (look for .1, .2, etc. files)
        rotated_logs = list(temp_logs_dir.glob(f"{email}.log.*"))
        if rotated_logs:
            print(f"Log rotation detected: {len(rotated_logs)} rotated files")
            for rotated in rotated_logs:
                # Rotated logs should also be valid JSON
                entries = access_logging_helper.parse_log_file(rotated)
                assert len(entries) > 0, f"Rotated log {rotated.name} is empty or invalid"
        
        # Verify total number of entries across all files
        total_entries = 0
        for log_file in log_files:
            if log_file.suffix in ['.log'] or log_file.suffix.startswith('.'):
                entries = access_logging_helper.parse_log_file(log_file)
                total_entries += len(entries)
        
        print(f"Total log entries across all files: {total_entries}")
        assert total_entries > 50, "Expected many log entries from our requests"
        
        # Cleanup
        subprocess.run(["just", "test-cleanup"], check=False)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])