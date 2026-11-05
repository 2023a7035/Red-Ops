"""
Test CVE Correlation Engine
Validates that software versions are mapped accurately to NVD records with CVSS 3.1 scores.
"""
import pytest
from services.cve_service import CVEService, CURATED_CVE_DB

def test_cve_database_integrity():
    assert len(CURATED_CVE_DB) >= 7
    for entry in CURATED_CVE_DB:
        assert entry["cve_id"].startswith("CVE-")
        assert entry["cvss_score"] > 0.0
        assert entry["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert "remediation" in entry
        assert "description" in entry

def test_version_matching():
    # Spring4Shell match
    spring_entry = next(e for e in CURATED_CVE_DB if e["cve_id"] == "CVE-2022-22965")
    assert spring_entry["version_check"]("Apache Tomcat 9.0.43 (Spring Boot 2.6.2)") is True
    assert spring_entry["version_check"]("Apache HTTP Server 2.4.49") is False

    # Redis Lua RCE match
    redis_entry = next(e for e in CURATED_CVE_DB if e["cve_id"] == "CVE-2022-0543")
    assert redis_entry["version_check"]("redis_version:5.0.7") is True
    assert redis_entry["version_check"]("mysql 8.0.28") is False

    # Zerologon match
    zero_entry = next(e for e in CURATED_CVE_DB if e["cve_id"] == "CVE-2020-1472")
    assert zero_entry["version_check"]("SMB Windows Server 2019") is True
    assert zero_entry["version_check"]("Ubuntu Linux 22.04") is False

def test_correlation_execution():
    result = CVEService.correlate_all_services()
    assert result["success"] is True
    assert result["total_correlated"] > 0
