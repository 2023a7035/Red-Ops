/**
 * RedOps Platform - Main Interface Controller
 */

document.addEventListener("DOMContentLoaded", () => {
    // 1. Live UTC Clock in Topbar
    const clockEl = document.getElementById("liveClock");
    if (clockEl) {
        const updateClock = () => {
            const now = new Date();
            clockEl.textContent = now.toUTCString().replace("GMT", "UTC");
        };
        updateClock();
        setInterval(updateClock, 1000);
    }
});

/**
 * Dispatches sleek cyber toast notifications.
 * @param {string} message - Message text
 * @param {string} type - 'info', 'success', 'error'
 */
function showToast(message, type = "info") {
    let container = document.getElementById("toastContainer");
    if (!container) {
        container = document.createElement("div");
        container.id = "toastContainer";
        container.className = "toast-container";
        document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    toast.className = `cyber-toast ${type === 'error' ? 'toast-error' : type === 'success' ? 'toast-success' : ''}`;
    toast.innerHTML = `<div>${message}</div>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateX(100%)";
        toast.style.transition = "all 0.3s ease";
        setTimeout(() => toast.remove(), 300);
    }, 4500);
}

/**
 * Global Modal Helpers
 */
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.style.display = "flex";
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.style.display = "none";
}
