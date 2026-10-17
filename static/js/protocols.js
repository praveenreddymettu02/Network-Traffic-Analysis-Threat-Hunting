document.addEventListener('DOMContentLoaded', function() {
    let protocolInterval = null;
    let isCaptureRunning = false;

    // Chart instances
    let timelineChart = null;
    let distributionChart = null;

    // ============================================
    // 🔥 FETCH PROTOCOL STATS
    // ============================================
    function fetchProtocolStats() {
        fetch('/api/stats')
            .then(res => {
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                return res.json();
            })
            .then(data => {
                // Update cards
                const protoDns = document.getElementById('proto-dns');
                if (protoDns) protoDns.innerText = (data.dns_count || 0).toLocaleString();
                const protoHttp = document.getElementById('proto-http');
                if (protoHttp) protoHttp.innerText = (data.http_count || 0).toLocaleString();
                const protoHttps = document.getElementById('proto-https');
                if (protoHttps) protoHttps.innerText = (data.https_count || 0).toLocaleString();
                const protoTcp = document.getElementById('proto-tcp');
                if (protoTcp) protoTcp.innerText = (data.tcp_count || 0).toLocaleString();
                const protoUdp = document.getElementById('proto-udp');
                if (protoUdp) protoUdp.innerText = (data.udp_count || 0).toLocaleString();
                const protoIcmp = document.getElementById('proto-icmp');
                if (protoIcmp) protoIcmp.innerText = (data.icmp_count || 0).toLocaleString();

                // Update packet count badge
                const countBadge = document.getElementById('proto-count-badge');
                if (countBadge) countBadge.innerText = (data.total_packets || 0).toLocaleString() + ' packets';
            })
            .catch(err => console.warn('Protocol stats fetch error:', err));

        // Fetch exact protocol breakdown from traffic endpoint
        fetch('/api/traffic/protocols')
            .then(res => res.json())
            .then(tData => {
                if (tData.protocols && tData.protocols.length > 0) {
                    updateProtocolTable(tData.protocols);
                }
            })
            .catch(() => {});
    }

    // ============================================
    // 📊 UPDATE PROTOCOL TABLE
    // ============================================
    function updateProtocolTable(protocolCounts) {
        const tbody = document.getElementById('protocol-details-body');
        if (!tbody) return;

        if (!protocolCounts || protocolCounts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No data available</td></tr>';
            return;
        }

        const sorted = [...protocolCounts].sort((a, b) => (b.total_bytes || b.count) - (a.total_bytes || a.count));
        const totalPackets = sorted.reduce((sum, p) => sum + (p.packet_count || p.count || 0), 0);

        tbody.innerHTML = sorted.map(p => {
            const count = p.packet_count !== undefined ? p.packet_count : p.count;
            const percentage = totalPackets > 0 ? ((count / totalPackets) * 100).toFixed(1) : 0;
            const protocol = p.protocol || 'Unknown';
            const bytesStr = p.total_bytes !== undefined ? formatBytes(p.total_bytes) : (p.bytes !== undefined ? formatBytes(p.bytes) : 'N/A');
            return `
                <tr>
                    <td><span class="badge bg-info">${protocol}</span></td>
                    <td>${count.toLocaleString()}</td>
                    <td>${percentage}%</td>
                    <td>${bytesStr}</td>
                </tr>
            `;
        }).join('');
    }

    // ============================================
    // 🔥 FETCH TOP DNS DOMAINS
    // ============================================
    function fetchTopDomains() {
        fetch('/api/dns/top')
            .then(res => res.json())
            .then(data => {
                const list = document.getElementById('top-dns-domains');
                if (!list) return;
                
                if (data.domains && data.domains.length > 0) {
                    list.innerHTML = data.domains.slice(0, 10).map((d, i) => `
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            <span><span class="badge bg-secondary me-2">${i + 1}</span>
                            <i class="fas fa-globe me-2" style="color: #8b5cf6;"></i>${d.domain}</span>
                            <span class="badge bg-primary rounded-pill">${d.count}</span>
                        </li>
                    `).join('');
                } else {
                    list.innerHTML = '<li class="list-group-item text-muted text-center">No DNS data yet</li>';
                }
            })
            .catch(err => console.warn('Top domains error:', err));
    }

    // ============================================
    // 🔥 FETCH ACTIVE HOSTS
    // ============================================
    function fetchActiveHosts() {
        fetch('/api/stats')
            .then(res => res.json())
            .then(data => {
                const list = document.getElementById('active-hosts');
                if (!list) return;
                
                const hosts = data.top_src_ips || [];
                if (hosts.length > 0) {
                    list.innerHTML = hosts.slice(0, 10).map((ip, i) => `
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            <span><span class="badge bg-secondary me-2">${i + 1}</span>
                            <i class="fas fa-server me-2" style="color: #ec4899;"></i>${ip.src_ip || 'Unknown'}</span>
                            <span class="badge bg-success rounded-pill">${ip.count} packets</span>
                        </li>
                    `).join('');
                } else {
                    list.innerHTML = '<li class="list-group-item text-muted text-center">No host data yet</li>';
                }
            })
            .catch(err => console.warn('Active hosts error:', err));
    }



    // ============================================
    // 🔄 START/STOP LIVE UPDATES
    // ============================================
    function startLiveUpdates() {
        if (protocolInterval) clearInterval(protocolInterval);
        
        // Fetch immediately
        fetchProtocolStats();
        fetchTopDomains();
        fetchActiveHosts();
        
        // Then every 5 seconds
        protocolInterval = setInterval(() => {
            fetchProtocolStats();
            fetchTopDomains();
            fetchActiveHosts();
        }, 5000);
        
        const statusEl = document.getElementById('proto-live-status');
        if (statusEl) statusEl.innerText = '🟢 Live';
        console.log('Protocols live updates started');
    }

    function stopLiveUpdates() {
        if (protocolInterval) {
            clearInterval(protocolInterval);
            protocolInterval = null;
        }
        const statusEl = document.getElementById('proto-live-status');
        if (statusEl) statusEl.innerText = '🔴 Stopped';
        console.log('Protocols live updates stopped');
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
                        // Show final data
                        fetchProtocolStats();
                        fetchTopDomains();
                        fetchActiveHosts();
                    }
                }
            })
            .catch(() => {});
    }

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
    // 🔄 LISTEN FOR CAPTURE EVENTS
    // ============================================
    document.addEventListener('captureStarted', function(e) {
        console.log('✅ Capture started, starting protocols live updates');
        isCaptureRunning = true;
        startLiveUpdates();
    });

    document.addEventListener('captureStopped', function(e) {
        console.log('❌ Capture stopped, stopping protocols live updates');
        isCaptureRunning = false;
        stopLiveUpdates();
    });

    // ============================================
    // 🔄 INITIALIZE
    // ============================================
    // Initial fetch
    fetchProtocolStats();
    fetchTopDomains();
    fetchActiveHosts();
    
    // Check capture status
    checkCaptureStatus();
    
    // Check status every 10 seconds
    setInterval(checkCaptureStatus, 10000);

    console.log('Protocols page initialized');
});