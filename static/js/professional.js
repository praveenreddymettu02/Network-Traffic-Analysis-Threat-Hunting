// ============================================
// 📊 PROFESSIONAL DASHBOARD - JavaScript
// ============================================

document.addEventListener('DOMContentLoaded', function() {

    // ============================================
    // 🔔 ALERT SYSTEM
    // ============================================
    let alerts = [];
    let alertCount = 0;

    function addAlert(type, message) {
        const alertObj = {
            id: Date.now(),
            type: type,
            message: message,
            time: new Date().toLocaleTimeString()
        };
        alerts.unshift(alertObj);
        if (alerts.length > 20) alerts.pop();
        alertCount = alerts.length;
        updateAlerts();
    }

    function updateAlerts() {
        const badge = document.getElementById('alert-count-badge');
        if (badge) badge.innerText = alertCount;
        
        const alertBadge = document.getElementById('alert-badge');
        if (alertBadge) {
            alertBadge.innerHTML = `<i class="fas fa-exclamation-triangle"></i> ${alertCount}`;
        }

        const list = document.getElementById('alerts-list');
        if (!list) return;
        
        if (alerts.length === 0) {
            list.innerHTML = `<div class="list-group-item text-muted text-center">No alerts</div>`;
            return;
        }
        list.innerHTML = alerts.slice(0, 10).map(a => `
            <div class="list-group-item list-group-item-${a.type} d-flex justify-content-between align-items-center" style="font-size: 0.85rem;">
                <span>${a.message}</span>
                <small class="text-muted">${a.time}</small>
            </div>
        `).join('');
    }

    // Real-time alerts fetched from API
    function fetchAlerts() {
        fetch('/api/alerts/recent')
            .then(res => res.json())
            .then(data => {
                if (Array.isArray(data)) {
                    alerts = data.map(a => ({
                        id: a.id,
                        type: a.type || 'info',
                        message: a.message || '',
                        time: a.time_local || ''
                    }));
                    alertCount = alerts.length;
                    updateAlerts();
                }
            })
            .catch(() => {});
    }

    // ============================================
    // 📈 REAL-TIME STATS
    // ============================================
    let startTime = Date.now();

    function updateLiveStats() {
        fetch('/api/live-stats')
            .then(res => res.json())
            .then(data => {
                const newCount = data.total_packets || 0;
                const totalEl = document.getElementById('total-packets');
                if (totalEl) totalEl.innerText = newCount.toLocaleString();
                
                const ppsEl = document.getElementById('pps-meter');
                if (ppsEl) ppsEl.innerText = Math.round(data.packets_per_second || 0).toLocaleString();
                
                const uptimeEl = document.getElementById('uptime');
                if (uptimeEl) {
                    const uptime = Math.floor((Date.now() - startTime) / 1000);
                    uptimeEl.innerText = formatUptime(uptime);
                }
                
                const cpuEl = document.getElementById('cpu-usage');
                if (cpuEl) cpuEl.innerText = Math.round(data.cpu_usage || 0) + '%';

                const memEl = document.getElementById('memory-usage');
                if (memEl) memEl.innerText = Math.round(data.memory_usage || 0) + '%';
                
                const sysCountEl = document.getElementById('system-packet-count');
                if (sysCountEl) sysCountEl.innerText = newCount.toLocaleString();
                
                updateCaptureStatus();
                fetchAlerts();
            })
            .catch(err => console.warn('Stats update error:', err));
    }

    function updateCaptureStatus() {
        fetch('/api/capture/status')
            .then(response => response.json())
            .then(data => {
                const statusEl = document.getElementById('capture-status');
                if (data.running) {
                    statusEl.innerText = '🟢 Running';
                    statusEl.className = 'badge-status running';
                } else {
                    statusEl.innerText = '🔴 Stopped';
                    statusEl.className = 'badge-status stopped';
                }
            })
            .catch(() => {});
    }

    function formatUptime(seconds) {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        
        if (days > 0) return `${days}d ${hours}h ${minutes}m`;
        if (hours > 0) return `${hours}h ${minutes}m ${secs}s`;
        if (minutes > 0) return `${minutes}m ${secs}s`;
        return `${secs}s`;
    }

    function formatBytes(bytes) {
        if (bytes === 0 || !bytes) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // ============================================
    // 📊 TOP TALKERS
    // ============================================
    function updateTopTalkers() {
        fetch('/api/top/talkers')
            .then(res => res.json())
            .then(data => {
                const tbody = document.getElementById('top-talkers-body');
                if (!tbody) return;
                if (!data || data.length === 0 || data.error) {
                    tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No data</td></tr>`;
                    return;
                }
                tbody.innerHTML = data.map((item, index) => `
                    <tr>
                        <td>#${index + 1}</td>
                        <td><span class="badge bg-dark">${item.ip || 'Unknown'}</span></td>
                        <td>${(item.packets || 0).toLocaleString()}</td>
                        <td>${formatBytes(item.bytes || 0)}</td>
                    </tr>
                `).join('');
            })
            .catch(err => {
                console.warn('Top talkers error:', err);
                const tbody = document.getElementById('top-talkers-body');
                if (tbody) tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">Error loading data</td></tr>`;
            });
    }

    // ============================================
    // 🖥️ SYSTEM INFO
    // ============================================
    function loadSystemInfo() {
        fetch('/api/system/info')
            .then(res => res.json())
            .then(data => {
                document.getElementById('system-os').innerText = data.os || 'Unknown';
                document.getElementById('system-python').innerText = data.python || 'Unknown';
                
                // Format DB size
                if (data.db_size !== undefined) {
                    const size = data.db_size;
                    if (size < 1024) {
                        document.getElementById('system-db-size').innerText = size + ' B';
                    } else if (size < 1024 * 1024) {
                        document.getElementById('system-db-size').innerText = (size / 1024).toFixed(1) + ' KB';
                    } else {
                        document.getElementById('system-db-size').innerText = (size / (1024 * 1024)).toFixed(1) + ' MB';
                    }
                }
            })
            .catch(err => console.warn('System info error:', err));
    }

    // ============================================
    // 🔄 START/STOP CAPTURE
    // ============================================
    document.addEventListener('click', function(e) {
        const startBtn = document.getElementById('start-capture');
        const stopBtn = document.getElementById('stop-capture');
        
        if (e.target === startBtn || e.target.closest('#start-capture')) {
            console.log('Start button clicked!');
            fetch('/api/capture/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            })
            .then(() => updateCaptureStatus())
            .catch(err => console.error('Start error:', err));
        }
        
        if (e.target === stopBtn || e.target.closest('#stop-capture')) {
            console.log('Stop button clicked!');
            fetch('/api/capture/stop', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            })
            .then(() => updateCaptureStatus())
            .catch(err => console.error('Stop error:', err));
        }
    });

    // ============================================
    // 🔄 INITIALIZE & AUTO-REFRESH
    // ============================================
    loadSystemInfo();
    updateLiveStats();
    updateTopTalkers();
    updateCaptureStatus();
    
    setInterval(updateLiveStats, 2000);
    setInterval(updateTopTalkers, 5000);
    setInterval(updateCaptureStatus, 3000);
});