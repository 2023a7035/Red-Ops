"""
Test AI Reasoning Module & Local Fallback
Validates deterministic security expert reasoning, risk scoring, and remediation output.
"""
import pytest
from services.llm_service import LLMService

def test_ai_reasoning_analysis():
    result = LLMService.analyze_path()
    assert result is not None
    assert "provider_label" in result
    assert "reasoning_text" in result
    assert len(result["reasoning_text"]) > 50

    # Ensure structured evidence is present
    assert "graph_evidence" in result
    assert "risk_factors" in result
    assert len(result["risk_factors"]) > 0

    # Ensure defensive recommendations are provided
    assert "defensive_recommendations" in result
    assert len(result["defensive_recommendations"]) > 0
    for rec in result["defensive_recommendations"]:
        assert "priority" in rec
        assert "action" in rec
        assert "detail" in rec

    # Ensure advisory limitations are preserved
    assert "limitations" in result
    assert "ADVISORY" in result["limitations"].upper()
