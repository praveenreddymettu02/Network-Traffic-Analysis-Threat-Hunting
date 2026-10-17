// ============================================
// 🔍 SOC THREAT HUNTING - JavaScript
// ============================================

document.addEventListener('DOMContentLoaded', function () {
    // Initial threat hunt execution
    runThreatHunt();
});

let huntAlertsMap = {};

function runThreatHunt() {
    const techId = document.getElementById('hunt-technique-id')?.value.trim() || '';
    const tactic = document.getElementById('hunt-tactic')?.value.trim() || '';
    const detType = document.getElementById('hunt-detection-type')?.value.trim() || '';
    const severity = document.getElementById('hunt-severity')?.value.trim() || '';
    const srcIp = document.getElementById('hunt-source-ip')?.value.trim() || '';

    const params = new URLSearchParams();
    if (techId) params.append('mitre_technique_id', techId);
    if (tactic) params.append('mitre_tactic', tactic);
    if (detType) params.append('detection_type', detType);
    if (severity) params.append('severity', severity);
    if (srcIp) params.append('source_ip', srcIp);

    const tbody = document.getElementById('hunt-results-tbody');
    if (tbody) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center text-info py-4">
                    <i class="fas fa-spinner fa-spin me-2"></i>Executing SOC database threat hunt query...
                </td>
            </tr>
        `;
    }

    fetch(`/api/hunting/search?${params.toString()}`)
        .then(res => res.json())
        .then(data => {
            const alerts = (data.status === 'success' && data.alerts) ? data.alerts : [];
            renderHuntResults(alerts);
        })
        .catch(err => {
            console.error('Error running threat hunt:', err);
            if (tbody) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="9" class="text-center text-danger py-4">❌ Threat hunt error: ${err.message}</td>
                    </tr>
                `;
            }
        });
}

function resetHuntFilters() {
    document.getElementById('hunt-technique-id').value = '';
    document.getElementById('hunt-tactic').value = '';
    document.getElementById('hunt-detection-type').value = '';
    document.getElementById('hunt-severity').value = '';
    document.getElementById('hunt-source-ip').value = '';
    runThreatHunt();
}

function renderHuntResults(alerts) {
    const tbody = document.getElementById('hunt-results-tbody');
    const badge = document.getElementById('hunt-count-badge');
    if (!tbody) return;

    huntAlertsMap = {};
    if (badge) badge.innerText = `${alerts.length} Detections Found`;

    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center text-muted py-4">No matching database threat alerts found for the specified hunting criteria.</td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = alerts.map(a => {
        huntAlertsMap[a.id] = a;
        const sevClass = a.severity === 'CRITICAL' ? 'badge bg-danger' :
            a.severity === 'HIGH' ? 'badge bg-warning text-dark' : 'badge bg-info text-dark';

        const mitreDisplay = a.mitre_technique_id ? `<code class="text-info">${a.mitre_technique_id}</code>` : '<span class="text-muted">Unmapped</span>';

        return `
            <tr>
                <td class="small text-muted">${a.time_local || 'N/A'}</td>
                <td><code>${a.detection_type || a.alert_type}</code></td>
                <td>${mitreDisplay}</td>
                <td><span class="badge bg-secondary">${a.mitre_tactic || 'N/A'}</span></td>
                <td><code>${a.source_ip || 'N/A'}</code></td>
                <td><code>${a.destination_ip || 'N/A'}</code></td>
                <td><span class="${sevClass}">${a.severity}</span></td>
                <td class="small text-truncate" style="max-width: 250px;">${a.evidence || a.details || a.description}</td>
                <td>
                    <button class="btn btn-xs btn-outline-warning" onclick="inspectHuntAlert(${a.id})">
                        <i class="fas fa-search me-1"></i>Inspect
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function inspectHuntAlert(alertId) {
    const alert = huntAlertsMap[alertId];
    if (!alert) return;

    const modalBody = document.getElementById('hunt-alert-modal-body');
    if (!modalBody) return;

    modalBody.innerHTML = `
        <div class="row g-3">
            <div class="col-md-6">
                <div class="p-3 rounded bg-black bg-opacity-50 border border-secondary">
                    <h6 class="text-info border-bottom border-secondary pb-2 mb-3"><i class="fas fa-info-circle me-2"></i>Alert Summary</h6>
                    <p class="mb-1"><strong>Detection Type:</strong> <code>${alert.detection_type || alert.alert_type}</code></p>
                    <p class="mb-1"><strong>Title:</strong> ${alert.title}</p>
                    <p class="mb-1"><strong>Description:</strong> ${alert.description}</p>
                    <p class="mb-1"><strong>Severity:</strong> <span class="badge bg-warning text-dark">${alert.severity}</span></p>
                    <p class="mb-0"><strong>Timestamp:</strong> ${alert.time_local || alert.timestamp}</p>
                </div>
            </div>

            <div class="col-md-6">
                <div class="p-3 rounded bg-black bg-opacity-50 border border-secondary">
                    <h6 class="text-danger border-bottom border-secondary pb-2 mb-3"><i class="fas fa-crosshairs me-2"></i>MITRE ATT&CK Context</h6>
                    <p class="mb-1"><strong>Technique ID:</strong> <code class="fs-6 text-info">${alert.mitre_technique_id || 'N/A'}</code></p>
                    <p class="mb-1"><strong>Technique Name:</strong> ${alert.mitre_technique_name || 'N/A'}</p>
                    <p class="mb-1"><strong>Tactic:</strong> <span class="badge bg-secondary">${alert.mitre_tactic || 'N/A'}</span></p>
                    <p class="mb-0"><strong>Mapping Confidence:</strong> <span class="badge border border-warning text-warning">${alert.mitre_status || 'Potential / Suspected'}</span></p>
                </div>
            </div>

            <div class="col-md-12">
                <div class="p-3 rounded bg-black bg-opacity-50 border border-secondary">
                    <h6 class="text-warning border-bottom border-secondary pb-2 mb-3"><i class="fas fa-terminal me-2"></i>Full Telemetry & Evidence</h6>
                    <div class="row g-2 small mb-3">
                        <div class="col-md-3"><strong>Source IP:</strong> <code>${alert.source_ip || 'N/A'}</code></div>
                        <div class="col-md-3"><strong>Destination IP:</strong> <code>${alert.destination_ip || 'N/A'}</code></div>
                        <div class="col-md-3"><strong>Protocol:</strong> <code>${alert.protocol || 'N/A'}</code></div>
                        <div class="col-md-3"><strong>Ports:</strong> <code>${alert.source_port || '*'} -> ${alert.destination_port || '*'}</code></div>
                    </div>
                    <div class="p-2 rounded bg-black text-success font-monospace small">
                        <strong>Evidence:</strong> ${alert.evidence || alert.details || 'No evidence recorded.'}
                    </div>
                </div>
            </div>
        </div>
    `;

    const modal = new bootstrap.Modal(document.getElementById('huntAlertModal'));
    modal.show();
}
