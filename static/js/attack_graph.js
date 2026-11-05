/**
 * RedOps Interactive Attack Graph Controller
 * Powered by Cytoscape.js & NetworkX backend data.
 */

let cy = null;

document.addEventListener("DOMContentLoaded", () => {
    initAttackGraph();

    // Layout switcher
    const layoutSelect = document.getElementById("cyLayoutSelect");
    if (layoutSelect) {
        layoutSelect.addEventListener("change", (e) => {
            changeLayout(e.target.value);
        });
    }

    // Path highlighter selector
    const pathSelect = document.getElementById("attackPathSelect");
    if (pathSelect) {
        pathSelect.addEventListener("change", (e) => {
            highlightPath(e.target.value);
        });
    }
});

async function initAttackGraph() {
    const cyContainer = document.getElementById("cy");
    if (!cyContainer) return;

    try {
        const response = await fetch("/api/graph/elements");
        const data = await response.json();

        if (!data.success || !data.elements) {
            console.error("Failed to load graph elements");
            return;
        }

        cy = cytoscape({
            container: cyContainer,
            elements: data.elements,
            style: [
                // Base Node Style
                {
                    selector: 'node',
                    style: {
                        'label': 'data(label)',
                        'text-valign': 'bottom',
                        'text-halign': 'center',
                        'text-margin-y': 6,
                        'font-size': '10px',
                        'font-family': 'Inter, sans-serif',
                        'color': '#8899b5',
                        'background-color': '#0d1b33',
                        'border-width': 2,
                        'border-color': '#1e2c4a',
                        'width': 36,
                        'height': 36,
                        'text-wrap': 'wrap',
                        'text-max-width': 120
                    }
                },
                // Threat Actor Entrypoint
                {
                    selector: 'node.type-entrypoint',
                    style: {
                        'shape': 'ellipse',
                        'background-color': '#ff2a5f',
                        'border-color': '#fff',
                        'border-width': 3,
                        'width': 44,
                        'height': 44,
                        'color': '#ff2a5f',
                        'font-weight': 'bold'
                    }
                },
                // Host Nodes
                {
                    selector: 'node.type-host',
                    style: {
                        'shape': 'round-rectangle',
                        'background-color': '#0077fe',
                        'border-color': '#00f0ff',
                        'border-width': 2,
                        'width': 42,
                        'height': 42,
                        'color': '#fff'
                    }
                },
                // Crown Jewel Target Nodes
                {
                    selector: 'node.type-target',
                    style: {
                        'shape': 'star',
                        'background-color': '#9d4edd',
                        'border-color': '#c77dff',
                        'border-width': 3,
                        'width': 50,
                        'height': 50,
                        'color': '#c77dff',
                        'font-weight': 'bold'
                    }
                },
                // Service Nodes
                {
                    selector: 'node.type-service',
                    style: {
                        'shape': 'hexagon',
                        'background-color': '#00f0ff',
                        'border-color': '#0077fe',
                        'border-width': 1,
                        'width': 30,
                        'height': 30,
                        'color': '#00f0ff'
                    }
                },
                // Vulnerability Nodes
                {
                    selector: 'node.type-vulnerability',
                    style: {
                        'shape': 'diamond',
                        'background-color': '#ff7700',
                        'border-color': '#ffb703',
                        'border-width': 2,
                        'width': 34,
                        'height': 34,
                        'color': '#ff7700'
                    }
                },
                {
                    selector: 'node.severity-critical',
                    style: {
                        'background-color': '#ff2a5f',
                        'border-color': '#fff',
                        'color': '#ff2a5f'
                    }
                },
                // Base Edge Style
                {
                    selector: 'edge',
                    style: {
                        'width': 1.5,
                        'line-color': '#1e2c4a',
                        'target-arrow-color': '#1e2c4a',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'bezier',
                        'arrow-scale': 0.8,
                        'font-size': '8px',
                        'color': '#546582'
                    }
                },
                // Perimeter Edges
                {
                    selector: 'edge.rel-perimeter_probe',
                    style: {
                        'line-color': '#00f0ff',
                        'target-arrow-color': '#00f0ff',
                        'line-style': 'dashed',
                        'width': 2
                    }
                },
                // Lateral Pivot Edges
                {
                    selector: 'edge.rel-lateral_internal_pivot',
                    style: {
                        'line-color': '#ff7700',
                        'target-arrow-color': '#ff7700',
                        'width': 2.5
                    }
                },
                // Compromise Edges
                {
                    selector: 'edge.rel-enables_host_compromise',
                    style: {
                        'line-color': '#ff2a5f',
                        'target-arrow-color': '#ff2a5f',
                        'width': 2.5
                    }
                },
                // Active Attack Path Highlight Styles
                {
                    selector: '.path-highlight-node',
                    style: {
                        'border-color': '#ff2a5f',
                        'border-width': 4,
                        'shadow-blur': 15,
                        'shadow-color': '#ff2a5f',
                        'shadow-opacity': 0.8
                    }
                },
                {
                    selector: '.path-highlight-edge',
                    style: {
                        'line-color': '#ff2a5f',
                        'target-arrow-color': '#ff2a5f',
                        'width': 4,
                        'shadow-blur': 12,
                        'shadow-color': '#ff2a5f',
                        'shadow-opacity': 0.9
                    }
                }
            ],
            layout: {
                name: 'cose',
                animate: true,
                padding: 40,
                componentSpacing: 100,
                nodeOverlap: 20,
                idealEdgeLength: 80
            }
        });

        // Click Event: Open Node Inspector
        cy.on('tap', 'node', (evt) => {
            const node = evt.target;
            openNodeInspector(node.data());
        });

        // Click on background closes inspector
        cy.on('tap', (evt) => {
            if (evt.target === cy) {
                closeNodeInspector();
            }
        });

    } catch (err) {
        console.error("Cytoscape initialization error:", err);
    }
}

function changeLayout(layoutName) {
    if (!cy) return;
    const layout = cy.layout({
        name: layoutName,
        animate: true,
        padding: 40
    });
    layout.run();
}

function openNodeInspector(data) {
    const inspector = document.getElementById("nodeInspector");
    if (!inspector) return;

    document.getElementById("inspTitle").textContent = data.label.replace("\n", " ");
    document.getElementById("inspType").textContent = data.type ? data.type.toUpperCase() : "NODE";
    document.getElementById("inspCriticality").textContent = data.criticality || data.severity || "STANDARD";
    document.getElementById("inspIp").textContent = data.ip ? `${data.ip} (${data.hostname || ''})` : "--";
    document.getElementById("inspPort").textContent = data.port ? `${data.port} / TCP` : "--";
    document.getElementById("inspCve").textContent = data.cve_id ? `${data.cve_id} (CVSS ${data.cvss_score})` : "--";
    document.getElementById("inspRemediation").textContent = data.remediation || data.description || "No specific remediation required for this node.";

    inspector.style.display = "block";
}

function closeNodeInspector() {
    const inspector = document.getElementById("nodeInspector");
    if (inspector) inspector.style.display = "none";
}

async function highlightPath(pathIndex) {
    if (!cy) return;

    // Reset previous highlights
    cy.elements().removeClass('path-highlight-node path-highlight-edge');

    if (pathIndex === "") return;

    try {
        const response = await fetch("/api/graph/paths");
        const data = await response.json();
        if (data.success && data.paths && data.paths[pathIndex]) {
            const chosenPath = data.paths[pathIndex];
            const steps = chosenPath.path_nodes || [];

            steps.forEach((step, idx) => {
                const node = cy.getElementById(step.node_id);
                if (node) node.addClass('path-highlight-node');

                if (idx < steps.length - 1) {
                    const nextStep = steps[idx + 1];
                    const edge = cy.edges(`[source = "${step.node_id}"][target = "${nextStep.node_id}"]`);
                    if (edge) edge.addClass('path-highlight-edge');
                }
            });

            showToast(`Highlighted: ${chosenPath.name} (Risk: ${chosenPath.risk_score})`, "info");
        }
    } catch (err) {
        console.error("Path highlight failed:", err);
    }
}

function fitGraph() {
    if (cy) cy.fit();
}
