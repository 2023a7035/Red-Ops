/**
 * RedOps Assessment Planner Controller
 * Handles user approval and execution of bounded assessment recommendations.
 */

document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".btn-execute-plan").forEach(btn => {
        btn.addEventListener("click", async () => {
            const planId = btn.getAttribute("data-plan-id");
            await runPlanStep(planId, btn);
        });
    });
});

async function runPlanStep(planId, btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="status-dot-pulse"></span> Processing...`;

    try {
        const response = await fetch(`/api/planner/execute/${planId}`, {
            method: "POST"
        });
        const data = await response.json();

        if (data.success) {
            showToast(data.message, "success");
            setTimeout(() => {
                window.location.reload();
            }, 1200);
        } else {
            showToast(data.error || "Execution failed.", "error");
            btn.disabled = false;
            btn.innerHTML = `Approve & Execute`;
        }
    } catch (err) {
        showToast("Error processing assessment step.", "error");
        btn.disabled = false;
        btn.innerHTML = `Approve & Execute`;
    }
}
