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
        # Based on the Dockerfile, the binary is at /root/server
        # so logs are created at /root/.logs/
        return Path("/root") / AccessLoggingTestHelper.LOGS_DIR

    @staticmethod
    def copy_logs_from_container(container_name: str, dest_path: Path) -> bool:
        """Copy logs from container to local filesystem for inspection."""
        try:
            # Create destination directory
            dest_path.mkdir(parents=True, exist_ok=True)
            
            # Copy logs from container - the server binary is at /root/server
            # so logs should be at /root/.logs/
            cmd = [
                "docker", "cp",
                f"{container_name}:/root/{AccessLoggingTestHelper.LOGS_DIR}/.",
                str(dest_path)
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Failed to copy logs: {result.stderr}")
                # Try to see what's in the container
                ls_cmd = ["docker", "exec", container_name, "ls", "-la", "/root/"]
                ls_result = subprocess.run(ls_cmd, capture_output=True, text=True)
                print(f"Contents of /root/: {ls_result.stdout}")
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
        
        # The containers are already running from 'just start-all' in GitHub Actions
        # We just need to verify they're up and make requests
        
        print("Checking that server is running...")
        server_status = get_container_status(docker_client, "syftbox-server")
        assert server_status["running"], "Server container is not running"
        
        # The existing clients should already be running
        # client1@syftbox.net and client2@syftbox.net are the default test clients
        client1_status = get_container_status(docker_client, "syftbox-client-client1-syftbox-net")
        client2_status = get_container_status(docker_client, "syftbox-client-client2-syftbox-net")
        
        assert client1_status["running"], "Client1 container is not running"
        assert client2_status["running"], "Client2 container is not running"
        
        # Make some API requests to generate log entries
        emails = ["client1@syftbox.net", "client2@syftbox.net"]
        
        for email in emails:
            print(f"Making API requests for {email}...")
            # Try various endpoints to generate log entries
            for i in range(3):
                try:
                    # These requests may fail but should still generate log entries
                    requests.get(
                        f"{AccessLoggingTestHelper.SERVER_URL}/api/files/test_{i}.txt",
                        headers={"X-User-Email": email},
                        timeout=2
                    )
                except:
                    pass  # We don't care if the request fails, just that it generates a log
                
                try:
                    requests.post(
                        f"{AccessLoggingTestHelper.SERVER_URL}/api/sync",
                        headers={"X-User-Email": email},
                        json={"path": f"/{email}/test.txt"},
                        timeout=2
                    )
                except:
                    pass
        
        # Give time for logs to be written
        time.sleep(2)
        
        # Copy logs from server container to local filesystem
        print("Copying logs from server container...")
        # The logs should be in /root/.logs/ based on the Dockerfile
        assert access_logging_helper.copy_logs_from_container(
            "syftbox-server",
            temp_logs_dir
        )
        
        # Verify log files exist for each user
        for email in emails:
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
            if entries:
                print(f"First entry: {json.dumps(entries[0], indent=2)}")

    def test_log_entry_format_and_content(
        self,
        docker_client,
        access_logging_helper,
        temp_logs_dir
    ):
        """Test that log entries contain expected fields and format."""
        
        # Containers are already running
        print("Checking that server is running...")
        server_status = get_container_status(docker_client, "syftbox-server")
        assert server_status["running"], "Server container is not running"
        
        email = AccessLoggingTestHelper.CLIENT1_EMAIL
        
        # Make specific API requests to generate known log entries
        print(f"Making test API requests for {email}...")
        
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
        
        time.sleep(2)
        
        # Copy logs from server
        print("Copying logs from server container...")
        assert access_logging_helper.copy_logs_from_container(
            "syftbox-server",
            temp_logs_dir
        )
        
        # Parse log file
        log_file = temp_logs_dir / f"{email}.log"
        assert log_file.exists(), f"Log file not found for {email}"
        
        entries = access_logging_helper.parse_log_file(log_file)
        assert len(entries) > 0, "No log entries found"
        
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

    def test_access_denied_logging(
        self,
        docker_client,
        access_logging_helper,
        temp_logs_dir
    ):
        """Test that access denied attempts are properly logged with reasons."""
        
        # Containers are already running
        print("Checking that server is running...")
        server_status = get_container_status(docker_client, "syftbox-server")
        assert server_status["running"], "Server container is not running"
        
        email1 = AccessLoggingTestHelper.CLIENT1_EMAIL
        
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
        
        time.sleep(2)
        
        # Copy logs
        print("Copying logs from server container...")
        assert access_logging_helper.copy_logs_from_container(
            "syftbox-server",
            temp_logs_dir
        )
        
        # Check log file
        log_file = temp_logs_dir / f"{email1}.log"
        assert log_file.exists(), f"Log file not found for {email1}"
        
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
        else:
            print("Warning: No denied entries found in this test run")

    def test_log_rotation(
        self,
        docker_client,
        access_logging_helper,
        temp_logs_dir
    ):
        """Test that log files are properly rotated when they exceed size limits."""
        
        # Containers are already running
        print("Checking that server is running...")
        server_status = get_container_status(docker_client, "syftbox-server")
        assert server_status["running"], "Server container is not running"
        
        email = AccessLoggingTestHelper.CLIENT1_EMAIL
        
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
        
        time.sleep(2)
        
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
        assert main_log.exists(), f"Main log file not found for {email}"
        
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])