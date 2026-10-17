document.addEventListener('DOMContentLoaded', function() {
    let tcpInterval = null;
    let isCaptureRunning = false;

    // ============================================
    // 🔥 FETCH TCP SESSIONS
    // ============================================
    function fetchTCPSessions() {
        fetch('/api/tcp/sessions')
            .then(res => {
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                return res.json();
            })
            .then(data => {
                console.log('TCP sessions:', data);
                updateTCPTable(data);
                updateTCPStats(data);
            })
            .catch(err => console.warn('TCP sessions error:', err));
    }

    // ============================================
    // 📊 UPDATE TCP TABLE
    // ============================================
    function updateTCPTable(sessions) {
        const tbody = document.getElementById('tcp-sessions-body');
        if (!tbody) return;

        if (!sessions || sessions.length === 0) {
            tbody.innerHTML = '<tr><td colspan="14" class="text-center text-muted">No TCP sessions yet</td></tr>';
            document.getElementById('session-count-badge').innerText = '0';
            return;
        }

        document.getElementById('session-count-badge').innerText = sessions.length;

        tbody.innerHTML = sessions.slice(0, 50).map((s, index) => {
            // Format duration
            let duration = '-';
            if (s.duration && s.duration > 0) {
                const hours = Math.floor(s.duration / 3600);
                const minutes = Math.floor((s.duration % 3600) / 60);
                const seconds = s.duration % 60;
                if (hours > 0) duration = `${hours}h ${minutes}m`;
                else if (minutes > 0) duration = `${minutes}m ${seconds}s`;
                else duration = `${seconds}s`;
            }

            // Status badge color
            let statusBadge = 'bg-success';
            if (s.status === 'active') statusBadge = 'bg-success';
            else if (s.status === 'syn_sent') statusBadge = 'bg-warning';
            else if (s.status === 'closed') statusBadge = 'bg-secondary';
            else if (s.status === 'reset') statusBadge = 'bg-danger';

            return `
                <tr>
                    <td><span class="badge bg-secondary">${index + 1}</span></td>
                    <td><span class="badge bg-light text-dark">${s.src_ip || 'N/A'}</span></td>
                    <td><span class="badge bg-dark">${s.src_port || 'N/A'}</span></td>
                    <td><span class="badge bg-light text-dark">${s.dst_ip || 'N/A'}</span></td>
                    <td><span class="badge bg-dark">${s.dst_port || 'N/A'}</span></td>
                    <td>${s.syn_count || 0}</td>
                    <td>${s.ack_count || 0}</td>
                    <td>${s.fin_count || 0}</td>
                    <td>${s.rst_count || 0}</td>
                    <td>${s.window_size || 0}</td>
                    <td>${(s.packet_count || 0).toLocaleString()}</td>
                    <td>${formatBytes(s.bytes_transferred || 0)}</td>
                    <td>${duration}</td>
                    <td><span class="badge ${statusBadge}">${s.status || 'unknown'}</span></td>
                </tr>
            `;
        }).join('');
    }

    // ============================================
    // 📊 UPDATE TCP STATS
    // ============================================
    function updateTCPStats(sessions) {
        if (!sessions || sessions.length === 0) {
            document.getElementById('tcp-total').innerText = '0';
            document.getElementById('tcp-active').innerText = '0';
            document.getElementById('tcp-closed').innerText = '0';
            document.getElementById('tcp-reset').innerText = '0';
            return;
        }

        const total = sessions.length;
        const active = sessions.filter(s => s.status === 'active' || s.status === 'syn_sent' || s.status === 'established').length;
        const closed = sessions.filter(s => s.status === 'closed').length;
        const reset = sessions.filter(s => s.status === 'reset').length;

        document.getElementById('tcp-total').innerText = total;
        document.getElementById('tcp-active').innerText = active;
        document.getElementById('tcp-closed').innerText = closed;
        document.getElementById('tcp-reset').innerText = reset;
    }

    // ============================================
    // 🔄 UPDATE TIME
    // ============================================
    function updateTime() {
        const now = new Date();
        document.getElementById('tcp-update-time').innerText = now.toLocaleTimeString();
    }

    // ============================================
    // 🔄 REFRESH SESSIONS
    // ============================================
    window.refreshSessions = function() {
        fetchTCPSessions();
        updateTime();
    };

    // ============================================
    // 📦 UTILITY FUNCTIONS
    // ============================================
    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    // ============================================
    // 🔄 START/STOP LIVE UPDATES
    // ============================================
    function startLiveUpdates() {
        if (tcpInterval) clearInterval(tcpInterval);
        
        fetchTCPSessions();
        updateTime();
        
        tcpInterval = setInterval(() => {
            fetchTCPSessions();
            updateTime();
        }, 5000);
        
        document.getElementById('tcp-live-status').innerText = '🟢 Live';
        console.log('TCP live updates started');
    }

    function stopLiveUpdates() {
        if (tcpInterval) {
            clearInterval(tcpInterval);
            tcpInterval = null;
        }
        document.getElementById('tcp-live-status').innerText = '🔴 Stopped';
        console.log('TCP live updates stopped');
    }

    // ============================================
    // 🔍 CHECK CAPTURE STATUS
    // ============================================
    function checkCaptureStatus() {
        fetch('/api/capture/status')
            .then(response => response.json())
            .then(data => {
                if (data.running) {
                    if (!isCaptureRunning) {
                        isCaptureRunning = true;
                        startLiveUpdates();
                    }
                } else {
                    if (isCaptureRunning) {
                        isCaptureRunning = false;
                        stopLiveUpdates();
                        fetchTCPSessions();
                    }
                }
            })
            .catch(() => {});
    }

    // ============================================
    // 🔄 LISTEN FOR CAPTURE EVENTS
    // ============================================
    document.addEventListener('captureStarted', function(e) {
        console.log('✅ Capture started, starting TCP live updates');
        isCaptureRunning = true;
        startLiveUpdates();
    });

    document.addEventListener('captureStopped', function(e) {
        console.log('❌ Capture stopped, stopping TCP live updates');
        isCaptureRunning = false;
        stopLiveUpdates();
    });

    // ============================================
    // 🔄 INITIALIZE
    // ============================================
    fetchTCPSessions();
    checkCaptureStatus();
    setInterval(checkCaptureStatus, 10000);

    console.log('TCP Analysis page initialized');
});