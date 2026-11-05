/**
 * RedOps Discovery Interface Controller
 * Triggers authorized scans, validates target scope, and renders live terminal output.
 */

document.addEventListener("DOMContentLoaded", () => {
    const scanForm = document.getElementById("scanForm");
    if (scanForm) {
        scanForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            await triggerScan();
        });
    }
});

async function triggerScan() {
    const targetInput = document.getElementById("targetInput");
    const profileSelect = document.getElementById("profileSelect");
    const terminalBody = document.getElementById("scanTerminalBody");
    const scanBtn = document.getElementById("startScanBtn");

    const target = targetInput.value.trim();
    const profile = profileSelect.value;

    if (!target) {
        showToast("Please enter an authorized target IP or subnet.", "error");
        return;
    }

    // Update UI to running state
    scanBtn.disabled = true;
    scanBtn.innerHTML = `<span class="status-dot-pulse"></span> Scanning...`;
    terminalBody.textContent = `[*] Initializing RedOps Security Scanner...\n[*] Target: ${target}\n[*] Profile: ${profile.toUpperCase()}\n[*] Verifying target authorization against security scope allowlist...\n`;

    try {
        const response = await fetch("/api/discovery/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target: target, profile: profile })
        });

        const data = await response.json();

        if (data.success) {
            terminalBody.textContent += data.raw_log || "[*] Scan completed successfully.";
            showToast(`Scan complete: Discovered ${data.hosts.length} hosts and ${data.ports_found} open ports.`, "success");
            setTimeout(() => {
                window.location.reload();
            }, 1800);
        } else {
            terminalBody.textContent += `\n[!] ERROR / POLICY ENFORCEMENT:\n${data.error || "Scan failed."}`;
            showToast(data.error || "Scan execution blocked or failed.", "error");
        }
    } catch (err) {
        terminalBody.textContent += `\n[!] Network or server communication error: ${err}`;
        showToast("Communication error with RedOps backend.", "error");
    } finally {
        scanBtn.disabled = false;
        scanBtn.innerHTML = `Start Authorized Scan`;
    }
}
