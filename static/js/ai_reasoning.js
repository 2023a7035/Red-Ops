/**
 * RedOps AI Threat Intelligence Controller
 * Triggers LLM / Expert Rule-Based reasoning and updates explanation cards.
 */

document.addEventListener("DOMContentLoaded", () => {
    const triggerBtn = document.getElementById("triggerAiBtn");
    if (triggerBtn) {
        triggerBtn.addEventListener("click", runAiAnalysis);
    }
});

async function runAiAnalysis() {
    const btn = document.getElementById("triggerAiBtn");
    const narrativeEl = document.getElementById("aiNarrativeText");
    const providerBadge = document.getElementById("aiProviderBadge");
    const riskContainer = document.getElementById("aiRiskFactorsContainer");
    const remContainer = document.getElementById("aiRemediationContainer");

    btn.disabled = true;
    btn.innerHTML = `<span class="status-dot-pulse"></span> Synthesizing Threat Intelligence...`;

    try {
        const response = await fetch("/api/ai/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({})
        });

        const data = await response.json();

        if (data.success && data.analysis) {
            const a = data.analysis;

            if (providerBadge) providerBadge.textContent = a.provider_label;
            if (narrativeEl) narrativeEl.textContent = a.reasoning_text;

            // Render Risk Factors
            if (riskContainer && a.risk_factors) {
                riskContainer.innerHTML = a.risk_factors.map(rf => `
                    <div style="display:flex; gap:10px; margin-bottom:8px; align-items:flex-start;">
                        <span style="color:#ff2a5f; font-weight:bold;">▸</span>
                        <div style="font-size:12px; color:#fff;">${rf}</div>
                    </div>
                `).join("");
            }

            // Render Recommendations
            if (remContainer && a.defensive_recommendations) {
                remContainer.innerHTML = a.defensive_recommendations.map(r => `
                    <div style="background:#0d1424; border:1px solid #1e2c4a; border-radius:6px; padding:12px; margin-bottom:10px;">
                        <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                            <span class="badge ${r.priority.includes('P0') ? 'badge-critical' : r.priority.includes('P1') ? 'badge-high' : 'badge-low'}">${r.priority}</span>
                            <span style="font-size:11px; color:#8899b5; font-family:monospace;">${r.mitre_tactic || ''}</span>
                        </div>
                        <div style="font-size:13px; font-weight:bold; color:#fff; margin-bottom:4px;">${r.action}</div>
                        <div style="font-size:12px; color:#8899b5;">${r.detail}</div>
                    </div>
                `).join("");
            }

            showToast("AI reasoning synthesized successfully.", "success");
        } else {
            showToast("Failed to generate AI analysis.", "error");
        }
    } catch (err) {
        console.error("AI reasoning trigger error:", err);
        showToast("Error communicating with AI reasoning service.", "error");
    } finally {
        btn.disabled = false;
        btn.innerHTML = `Synthesize Threat Narrative`;
    }
}
