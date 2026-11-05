"""
Test Allowlist Policy Enforcement
Validates that RedOps strictly blocks unauthorized targets and allows explicitly approved laboratory targets.
"""
import pytest
from config import Config

def test_authorized_targets():
    # Loopback targets
    assert Config.is_target_authorized("127.0.0.1") is True
    assert Config.is_target_authorized("localhost") is True

    # Lab Docker Subnet targets
    assert Config.is_target_authorized("172.28.0.10") is True
    assert Config.is_target_authorized("172.28.0.20") is True
    assert Config.is_target_authorized("172.28.0.30") is True
    assert Config.is_target_authorized("172.28.0.40") is True
    assert Config.is_target_authorized("172.28.0.100") is True

def test_blocked_unauthorized_targets():
    # Public Internet IPs must be blocked
    assert Config.is_target_authorized("8.8.8.8") is False
    assert Config.is_target_authorized("1.1.1.1") is False
    assert Config.is_target_authorized("142.250.190.46") is False

    # Arbitrary unauthorized subnets
    assert Config.is_target_authorized("198.51.100.1") is False
    assert Config.is_target_authorized("203.0.113.5") is False

    # Arbitrary domains
    assert Config.is_target_authorized("google.com") is False
    assert Config.is_target_authorized("target-organization.com") is False

def test_empty_target():
    assert Config.is_target_authorized("") is False
    assert Config.is_target_authorized(None) is False
