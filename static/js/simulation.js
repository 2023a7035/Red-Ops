/**
 * RedOps Controlled Simulation Controller
 * Manages operator approval modal, live terminal execution logs, and scenario selection.
 */

let selectedScenarioId = null;

document.addEventListener("DOMContentLoaded", () => {
    // Select scenario triggers
    document.querySelectorAll(".btn-launch-sim").forEach(btn => {
        btn.addEventListener("click", (e) => {
            const sid = btn.getAttribute("data-scenario-id");
            const scode = btn.getAttribute("data-scenario-code");
            const sname = btn.getAttribute("data-scenario-name");
            openApprovalModal(sid, scode, sname);
        });
    });

    // Modal confirm button
    const confirmBtn = document.getElementById("confirmApprovalBtn");
    if (confirmBtn) {
        confirmBtn.addEventListener("click", executeApprovedSimulation);
    }
});

function openApprovalModal(id, code, name) {
    selectedScenarioId = id;
    document.getElementById("modalScenarioName").textContent = `${code}: ${name}`;
    openModal("approvalModal");
}

async function executeApprovedSimulation() {
    const targetIp = document.getElementById("simTargetIp").value.trim();
    const targetPort = document.getElementById("simTargetPort").value.trim() || 80;
    const operatorName = document.getElementById("simOperatorName").value.trim() || "security_analyst";
    const terminalBody = document.getElementById("simTerminalBody");
    const confirmBtn = document.getElementById("confirmApprovalBtn");

    if (!targetIp) {
        showToast("Target IP is required.", "error");
        return;
    }

    closeModal("approvalModal");

    confirmBtn.disabled = true;
    terminalBody.textContent = `[*] Initiating authorized simulation...\n[*] Target: ${targetIp}:${targetPort}\n[*] Operator: ${operatorName}\n[*] Validating safety policy and allowlist scope...\n`;

    try {
        const response = await fetch("/api/simulation/execute", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                scenario_id: selectedScenarioId,
                target_ip: targetIp,
                target_port: parseInt(targetPort),
                approved_by: operatorName
            })
        });

        const data = await response.json();

        if (data.success) {
            terminalBody.textContent += data.logs || "[*] Simulation completed.";
            showToast(`Simulation completed: ${data.scenario}`, "success");
            setTimeout(() => {
                window.location.reload();
            }, 2000);
        } else {
            terminalBody.textContent += `\n[!] EXECUTION BLOCKED / FAILED:\n${data.error || "Simulation error."}\n${data.logs || ""}`;
            showToast(data.error || "Simulation failed or blocked.", "error");
        }
    } catch (err) {
        terminalBody.textContent += `\n[!] Communication exception: ${err}`;
        showToast("Error communicating with simulation backend.", "error");
    } finally {
        confirmBtn.disabled = false;
    }
}
