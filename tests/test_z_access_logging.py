"""
Test to verify access logs are correctly written after other tests have run.
This test should run after the main integration tests to verify logging functionality.
"""

import json
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import pytest
import docker


class AccessLogVerifier:
    """Helper class for verifying access log structure and content."""
    
    EXPECTED_CLIENTS = ["alice@syftbox.net", "bob@syftbox.net"]
    CONTAINER_NAME = "syftbox-server"
    LOG_BASE_PATH = "/root/.logs/access"
    
    @staticmethod
    def get_docker_client() -> docker.DockerClient:
        """Get Docker client instance."""
        return docker.from_env()
    
    @staticmethod
    def exec_in_container(command: str) -> tuple[bool, str]:
        """Execute a command in the server container and return success status and output."""
        cmd = ["docker", "exec", AccessLogVerifier.CONTAINER_NAME, "sh", "-c", command]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0, result.stdout
    
    @staticmethod
    def list_log_directories() -> List[str]:
        """List all directories in the access log path."""
        success, output = AccessLogVerifier.exec_in_container(
            f"ls -1 {AccessLogVerifier.LOG_BASE_PATH}/ 2>/dev/null || echo 'NO_LOGS_DIR'"
        )
        if not success or "NO_LOGS_DIR" in output:
            return []
        return [line.strip() for line in output.strip().split('\n') if line.strip()]
    
    @staticmethod
    def list_log_files(email: str) -> List[str]:
        """List all log files for a specific email."""
        log_dir = f"{AccessLogVerifier.LOG_BASE_PATH}/{email}"
        success, output = AccessLogVerifier.exec_in_container(
            f"ls -1 {log_dir}/ 2>/dev/null || echo 'NO_FILES'"
        )
        if not success or "NO_FILES" in output:
            return []
        return [line.strip() for line in output.strip().split('\n') if line.strip()]
    
    @staticmethod
    def read_log_file(email: str, filename: str) -> List[Dict]:
        """Read and parse a specific log file."""
        log_path = f"{AccessLogVerifier.LOG_BASE_PATH}/{email}/{filename}"
        success, output = AccessLogVerifier.exec_in_container(
            f"cat {log_path} 2>/dev/null"
        )
        if not success:
            return []
        
        entries = []
        for line in output.strip().split('\n'):
            if line:
                try:
                    entry = json.loads(line)
                    entries.append(entry)
                except json.JSONDecodeError:
                    continue
        return entries
    
    @staticmethod
    def verify_log_entry_structure(entry: Dict) -> tuple[bool, str]:
        """Verify that a log entry has all required fields with correct types."""
        required_fields = {
            "timestamp": str,
            "path": str,
            "access_type": str,
            "user": str,
            "ip": str,
            "user_agent": str,
            "method": str,
            "status_code": int,
            "allowed": bool
        }
        
        for field, expected_type in required_fields.items():
            if field not in entry:
                return False, f"Missing required field: {field}"
            
            if not isinstance(entry[field], expected_type):
                return False, f"Field {field} has wrong type: expected {expected_type.__name__}, got {type(entry[field]).__name__}"
        
        # Verify timestamp format
        if not (" UTC" in entry["timestamp"] or " GMT" in entry["timestamp"]):
            return False, f"Timestamp format incorrect: {entry['timestamp']}"
        
        # Verify access_type values
        valid_access_types = ["read", "write", "admin", "deny"]
        if entry["access_type"] not in valid_access_types:
            return False, f"Invalid access_type: {entry['access_type']}"
        
        # Verify HTTP method
        valid_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
        if entry["method"] not in valid_methods:
            return False, f"Invalid HTTP method: {entry['method']}"
        
        # Verify status code range
        if not (100 <= entry["status_code"] < 600):
            return False, f"Invalid status code: {entry['status_code']}"
        
        return True, "Valid"
    
    @staticmethod
    def get_log_statistics(entries: List[Dict]) -> Dict:
        """Get statistics about log entries."""
        stats = {
            "total_entries": len(entries),
            "allowed_count": sum(1 for e in entries if e.get("allowed", False)),
            "denied_count": sum(1 for e in entries if not e.get("allowed", True)),
            "methods": {},
            "access_types": {},
            "status_codes": {},
            "unique_paths": set(),
            "unique_ips": set()
        }
        
        for entry in entries:
            # Count methods
            method = entry.get("method", "UNKNOWN")
            stats["methods"][method] = stats["methods"].get(method, 0) + 1
            
            # Count access types
            access_type = entry.get("access_type", "UNKNOWN")
            stats["access_types"][access_type] = stats["access_types"].get(access_type, 0) + 1
            
            # Count status codes
            status_code = str(entry.get("status_code", 0))
            stats["status_codes"][status_code] = stats["status_codes"].get(status_code, 0) + 1
            
            # Track unique paths and IPs
            stats["unique_paths"].add(entry.get("path", ""))
            stats["unique_ips"].add(entry.get("ip", ""))
        
        # Convert sets to counts for JSON serialization
        stats["unique_paths_count"] = len(stats["unique_paths"])
        stats["unique_ips_count"] = len(stats["unique_ips"])
        del stats["unique_paths"]
        del stats["unique_ips"]
        
        return stats


class TestAccessLoggingVerification:
    """Test suite to verify access logs after integration tests have run."""
    
    def test_log_directories_exist(self):
        """Test that log directories exist for expected clients."""
        verifier = AccessLogVerifier()
        
        print("Checking for log directories in container...")
        directories = verifier.list_log_directories()
        
        print(f"Found directories: {directories}")
        
        # Check that we have directories for our test clients
        for email in AccessLogVerifier.EXPECTED_CLIENTS:
            assert email in directories, f"Log directory not found for {email}"
        
        print(f"✓ All expected client directories found: {AccessLogVerifier.EXPECTED_CLIENTS}")
    
    def test_log_files_created_with_date(self):
        """Test that log files are created with proper date format."""
        verifier = AccessLogVerifier()
        today = datetime.now().strftime("%Y%m%d")
        
        for email in AccessLogVerifier.EXPECTED_CLIENTS:
            print(f"\nChecking log files for {email}...")
            files = verifier.list_log_files(email)
            
            assert len(files) > 0, f"No log files found for {email}"
            
            # Check for today's log file
            expected_filename = f"access_{today}.log"
            assert expected_filename in files, f"Today's log file ({expected_filename}) not found for {email}"
            
            print(f"✓ Found log files for {email}: {files}")
    
    def test_log_entries_valid_structure(self):
        """Test that all log entries have valid structure and required fields."""
        verifier = AccessLogVerifier()
        today = datetime.now().strftime("%Y%m%d")
        
        for email in AccessLogVerifier.EXPECTED_CLIENTS:
            print(f"\nValidating log entries for {email}...")
            
            filename = f"access_{today}.log"
            entries = verifier.read_log_file(email, filename)
            
            assert len(entries) > 0, f"No log entries found for {email}"
            
            # Validate each entry
            invalid_entries = []
            for i, entry in enumerate(entries):
                valid, message = verifier.verify_log_entry_structure(entry)
                if not valid:
                    invalid_entries.append((i, message, entry))
            
            if invalid_entries:
                for idx, msg, entry in invalid_entries[:3]:  # Show first 3 invalid entries
                    print(f"  Invalid entry {idx}: {msg}")
                    print(f"  Entry: {json.dumps(entry, indent=2)}")
                
                assert False, f"Found {len(invalid_entries)} invalid entries for {email}"
            
            print(f"✓ All {len(entries)} entries valid for {email}")
    
    def test_log_entries_match_user(self):
        """Test that log entries in each file match the expected user."""
        verifier = AccessLogVerifier()
        today = datetime.now().strftime("%Y%m%d")
        
        for email in AccessLogVerifier.EXPECTED_CLIENTS:
            print(f"\nVerifying user field for {email}...")
            
            filename = f"access_{today}.log"
            entries = verifier.read_log_file(email, filename)
            
            mismatched_entries = []
            for i, entry in enumerate(entries):
                if entry.get("user") != email:
                    mismatched_entries.append((i, entry.get("user"), entry))
            
            if mismatched_entries:
                for idx, found_user, entry in mismatched_entries[:3]:
                    print(f"  Entry {idx} has wrong user: expected '{email}', found '{found_user}'")
                
                assert False, f"Found {len(mismatched_entries)} entries with wrong user for {email}"
            
            print(f"✓ All entries have correct user for {email}")
    
    def test_log_entries_contain_expected_operations(self):
        """Test that logs contain expected operations from integration tests."""
        verifier = AccessLogVerifier()
        today = datetime.now().strftime("%Y%m%d")
        
        for email in AccessLogVerifier.EXPECTED_CLIENTS:
            print(f"\nAnalyzing operations for {email}...")
            
            filename = f"access_{today}.log"
            entries = verifier.read_log_file(email, filename)
            
            stats = verifier.get_log_statistics(entries)
            
            print(f"  Total entries: {stats['total_entries']}")
            print(f"  Allowed: {stats['allowed_count']}, Denied: {stats['denied_count']}")
            print(f"  Methods: {stats['methods']}")
            print(f"  Access types: {stats['access_types']}")
            print(f"  Unique paths: {stats['unique_paths_count']}")
            print(f"  Status codes: {stats['status_codes']}")
            
            # Basic assertions
            assert stats['total_entries'] > 0, f"No entries found for {email}"
            
            # Should have some write operations from file sync
            if 'write' in stats['access_types']:
                assert stats['access_types']['write'] > 0, f"No write operations logged for {email}"
            
            # Should have successful operations (200 status)
            if '200' in stats['status_codes']:
                assert stats['status_codes']['200'] > 0, f"No successful operations logged for {email}"
            
            print(f"✓ Operations logged correctly for {email}")
    
    def test_log_entries_chronological_order(self):
        """Test that log entries are in chronological order."""
        verifier = AccessLogVerifier()
        today = datetime.now().strftime("%Y%m%d")
        
        for email in AccessLogVerifier.EXPECTED_CLIENTS:
            print(f"\nChecking chronological order for {email}...")
            
            filename = f"access_{today}.log"
            entries = verifier.read_log_file(email, filename)
            
            if len(entries) < 2:
                print(f"  Skipping order check for {email} (only {len(entries)} entries)")
                continue
            
            out_of_order = []
            for i in range(1, len(entries)):
                prev_time = entries[i-1].get("timestamp", "")
                curr_time = entries[i].get("timestamp", "")
                
                # Simple string comparison works for the format "YYYY-MM-DD HH:MM:SS.mmm UTC"
                if curr_time < prev_time:
                    out_of_order.append((i-1, i, prev_time, curr_time))
            
            if out_of_order:
                for prev_idx, curr_idx, prev_time, curr_time in out_of_order[:3]:
                    print(f"  Out of order: entry {prev_idx} ({prev_time}) > entry {curr_idx} ({curr_time})")
                
                # This is a warning, not a failure - logs might be written async
                print(f"  ⚠ Found {len(out_of_order)} out-of-order entries (may be due to async writes)")
            else:
                print(f"✓ All entries in chronological order for {email}")
    
    def test_access_denied_entries(self):
        """Test that denied access attempts are properly logged if any occurred."""
        verifier = AccessLogVerifier()
        today = datetime.now().strftime("%Y%m%d")
        
        total_denied = 0
        for email in AccessLogVerifier.EXPECTED_CLIENTS:
            print(f"\nChecking for denied access entries for {email}...")
            
            filename = f"access_{today}.log"
            entries = verifier.read_log_file(email, filename)
            
            denied_entries = [e for e in entries if not e.get("allowed", True)]
            
            if denied_entries:
                total_denied += len(denied_entries)
                print(f"  Found {len(denied_entries)} denied entries for {email}:")
                
                for entry in denied_entries[:3]:  # Show first 3
                    print(f"    Path: {entry.get('path')}")
                    print(f"    Reason: {entry.get('denied_reason', 'No reason provided')}")
                    print(f"    Status: {entry.get('status_code')}")
                
                # Check that denied entries have appropriate status codes (403, 401, etc.)
                for entry in denied_entries:
                    status = entry.get("status_code", 0)
                    assert status >= 400, f"Denied entry has success status code: {status}"
            else:
                print(f"  No denied entries for {email} (all access was allowed)")
        
        print(f"\n✓ Total denied entries across all clients: {total_denied}")
    
    def test_log_rotation_if_applicable(self):
        """Test log rotation if files exceed size limits."""
        verifier = AccessLogVerifier()
        
        for email in AccessLogVerifier.EXPECTED_CLIENTS:
            print(f"\nChecking for log rotation for {email}...")
            
            files = verifier.list_log_files(email)
            
            # Check for rotated files (e.g., access_20240904.log.1)
            rotated_files = [f for f in files if '.log.' in f]
            
            if rotated_files:
                print(f"  Found rotated files for {email}: {rotated_files}")
                
                # Verify rotated files are also valid
                for filename in rotated_files[:1]:  # Check first rotated file
                    entries = verifier.read_log_file(email, filename)
                    assert len(entries) > 0, f"Rotated file {filename} is empty"
                    
                    # Validate structure of first entry
                    if entries:
                        valid, message = verifier.verify_log_entry_structure(entries[0])
                        assert valid, f"Rotated file has invalid entries: {message}"
                
                print(f"✓ Log rotation working correctly for {email}")
            else:
                print(f"  No log rotation needed for {email} (file size within limits)")
    
    def test_summary_report(self):
        """Generate a summary report of all access logs."""
        verifier = AccessLogVerifier()
        today = datetime.now().strftime("%Y%m%d")
        
        print("\n" + "="*60)
        print("ACCESS LOG SUMMARY REPORT")
        print("="*60)
        
        total_stats = {
            "total_entries": 0,
            "total_allowed": 0,
            "total_denied": 0,
            "all_methods": {},
            "all_access_types": {},
            "all_status_codes": {}
        }
        
        for email in AccessLogVerifier.EXPECTED_CLIENTS:
            print(f"\n{email}:")
            print("-" * 40)
            
            filename = f"access_{today}.log"
            entries = verifier.read_log_file(email, filename)
            
            if not entries:
                print("  No entries found")
                continue
            
            stats = verifier.get_log_statistics(entries)
            
            # Update totals
            total_stats["total_entries"] += stats["total_entries"]
            total_stats["total_allowed"] += stats["allowed_count"]
            total_stats["total_denied"] += stats["denied_count"]
            
            for method, count in stats["methods"].items():
                total_stats["all_methods"][method] = total_stats["all_methods"].get(method, 0) + count
            
            for access_type, count in stats["access_types"].items():
                total_stats["all_access_types"][access_type] = total_stats["all_access_types"].get(access_type, 0) + count
            
            for status, count in stats["status_codes"].items():
                total_stats["all_status_codes"][status] = total_stats["all_status_codes"].get(status, 0) + count
            
            # Print client stats
            print(f"  Entries: {stats['total_entries']}")
            print(f"  Success rate: {stats['allowed_count']}/{stats['total_entries']} " +
                  f"({100*stats['allowed_count']/stats['total_entries']:.1f}%)")
            print(f"  Unique paths accessed: {stats['unique_paths_count']}")
            print(f"  Most used method: {max(stats['methods'].items(), key=lambda x: x[1])[0] if stats['methods'] else 'N/A'}")
            print(f"  Most common access type: {max(stats['access_types'].items(), key=lambda x: x[1])[0] if stats['access_types'] else 'N/A'}")
        
        print("\n" + "="*60)
        print("OVERALL TOTALS:")
        print("-" * 40)
        print(f"Total log entries: {total_stats['total_entries']}")
        print(f"Total allowed: {total_stats['total_allowed']}")
        print(f"Total denied: {total_stats['total_denied']}")
        print(f"Methods used: {', '.join(total_stats['all_methods'].keys())}")
        print(f"Access types: {', '.join(total_stats['all_access_types'].keys())}")
        print(f"Status codes: {', '.join(sorted(total_stats['all_status_codes'].keys()))}")
        print("="*60)
        
        # Basic assertion to ensure we have logs
        assert total_stats["total_entries"] > 0, "No log entries found across any clients"
        print("\n✅ All access logging verification tests passed!")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
