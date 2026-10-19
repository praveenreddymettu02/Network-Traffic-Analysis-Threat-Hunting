document.addEventListener('DOMContentLoaded', function() {
    const totalPacketsEl = document.getElementById('total-packets');
    const captureStatusEl = document.getElementById('capture-status');
    const protocolChartCtx = document.getElementById('protocol-chart')?.getContext('2d');
    let protocolChart;
    let liveInterval = null;
    let currentSessionId = null;

    // Protocol card references
    const dnsCountEl = document.getElementById('dns-count');
    const httpCountEl = document.getElementById('http-count');
    const httpsCountEl = document.getElementById('https-count');
    const tcpCountEl = document.getElementById('tcp-count');
    const udpCountEl = document.getElementById('udp-count');
    const icmpCountEl = document.getElementById('icmp-count');
    const arpCountEl = document.getElementById('arp-count');
    const bandwidthEl = document.getElementById('bandwidth-val');
    const ppsEl = document.getElementById('pps-meter');
    const cpuEl = document.getElementById('cpu-usage');
    const memEl = document.getElementById('memory-usage');
    const uptimeEl = document.getElementById('uptime');
    const sysPacketsEl = document.getElementById('system-packet-count');

    const COLORS = ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40', '#C9CBCF', '#FF6B6B'];

    let startTime = Date.now();

    function clearDashboard() {
        if (totalPacketsEl) totalPacketsEl.innerText = '0';
        if (dnsCountEl) dnsCountEl.innerText = '0';
        if (httpCountEl) httpCountEl.innerText = '0';
        if (httpsCountEl) httpsCountEl.innerText = '0';
        if (tcpCountEl) tcpCountEl.innerText = '0';
        if (udpCountEl) udpCountEl.innerText = '0';
        if (icmpCountEl) icmpCountEl.innerText = '0';
        if (arpCountEl) arpCountEl.innerText = '0';
        if (bandwidthEl) bandwidthEl.innerText = '0 B/s';
        if (ppsEl) ppsEl.innerText = '0';
        if (cpuEl) cpuEl.innerText = '0%';
        if (memEl) memEl.innerText = '0%';
        if (uptimeEl) uptimeEl.innerText = '0s';
        if (sysPacketsEl) sysPacketsEl.innerText = '0';
        
        updateProtocolChart([]);
        
        const srcList = document.getElementById('top-src-ips');
        if (srcList) srcList.innerHTML = '<li class="list-group-item text-muted text-center">No data</li>';
        
        const dstList = document.getElementById('top-dst-ips');
        if (dstList) dstList.innerHTML = '<li class="list-group-item text-muted text-center">No data</li>';
        
        const recentTable = document.querySelector('#recent-packets tbody');
        if (recentTable) recentTable.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-3">No packets captured yet.</td></tr>';
        
        const alertsList = document.getElementById('alerts-list');
        if (alertsList) alertsList.innerHTML = '<div class="list-group-item text-muted text-center">No alerts</div>';
        
        const alertBadge = document.getElementById('alert-badge');
        if (alertBadge) alertBadge.innerText = '0';
        const alertCountBadge = document.getElementById('alert-count-badge');
        if (alertCountBadge) alertCountBadge.innerText = '0';
    }

    function fetchLiveStats() {
        fetch('/api/live-stats')
            .then(response => {
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                return response.json();
            })
            .then(data => {
                if (data.status === 'no_session' && (!data.total_packets || data.total_packets === 0)) {
                    clearDashboard();
                    updateCaptureStatus(false);
                    return;
                }

                // Update all stats cards
                if (totalPacketsEl) totalPacketsEl.innerText = (data.total_packets || 0).toLocaleString();
                if (dnsCountEl) dnsCountEl.innerText = (data.dns_count || data.dns_queries || 0).toLocaleString();
                if (httpCountEl) httpCountEl.innerText = (data.http_count || data.http_requests || 0).toLocaleString();
                if (httpsCountEl) httpsCountEl.innerText = (data.https_count || data.https_connections || 0).toLocaleString();
                if (tcpCountEl) tcpCountEl.innerText = (data.tcp_count || data.tcp_packets || 0).toLocaleString();
                if (udpCountEl) udpCountEl.innerText = (data.udp_count || data.udp_packets || 0).toLocaleString();
                if (icmpCountEl) icmpCountEl.innerText = (data.icmp_count || data.icmp_packets || 0).toLocaleString();
                if (arpCountEl) arpCountEl.innerText = (data.arp_count || data.arp_packets || 0).toLocaleString();
                if (bandwidthEl) bandwidthEl.innerText = formatBytes(data.bandwidth || 0) + '/s';
                
                if (ppsEl) ppsEl.innerText = (data.packets_per_second || 0).toFixed(1);
                
                // 🔥 Real CPU and Memory from psutil via API
                if (cpuEl) cpuEl.innerText = (data.cpu_usage || 0) + '%';
                if (memEl) memEl.innerText = (data.memory_usage || 0) + '%';
                
                const uptime = Math.floor((Date.now() - startTime) / 1000);
                if (uptimeEl) uptimeEl.innerText = formatUptime(uptime);
                
                if (sysPacketsEl) sysPacketsEl.innerText = (data.total_packets || 0).toLocaleString();

                updateProtocolChart(data.protocol_counts || []);
                updateTopIPs(data.top_src_ips, data.top_dst_ips);
                updateCaptureStatus(data.is_running || false, currentCanCapture, '', isSimulationMode);
                updateTopTalkers();
                if (typeof window.fetchDNSQueries === 'function') {
                    window.fetchDNSQueries();
                }
                
                // 🔥 Fetch alerts separately
                fetchRecentAlerts();
            })
            .catch(err => {
                console.warn('Live stats fetch error:', err);
                fetchStats();
            });
    }

    // 🔥 Fetch Recent Alerts
    function fetchRecentAlerts() {
        // Fetch stats to update badges
        fetch('/api/alerts/stats')
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success' && data.stats) {
                    const totalAlerts = data.stats.total || 0;
                    const alertBadge = document.getElementById('alert-badge');
                    const alertCountBadge = document.getElementById('alert-count-badge');
                    if (alertBadge) alertBadge.innerText = totalAlerts.toLocaleString();
                    if (alertCountBadge) alertCountBadge.innerText = totalAlerts.toLocaleString();
                }
            })
            .catch(err => console.warn('Alert stats fetch error:', err));

        fetch('/api/alerts/recent')
            .then(response => response.json())
            .then(alerts => {
                const alertsList = document.getElementById('alerts-list');
                if (!alertsList) return;
                
                if (!alerts || alerts.length === 0) {
                    alertsList.innerHTML = '<div class="list-group-item text-muted text-center">No alerts</div>';
                    return;
                }
                
                alertsList.innerHTML = alerts.map(a => {
                    const bgClass = a.type === 'danger' ? 'list-group-item-danger' : 
                                   a.type === 'warning' ? 'list-group-item-warning' : 
                                   a.type === 'success' ? 'list-group-item-success' : '';
                    const mitreBadge = a.mitre_technique_id ? `<span class="badge bg-dark border border-danger text-danger ms-2">${a.mitre_technique_id}</span>` : '';
                    return `<div class="list-group-item ${bgClass} d-flex justify-content-between align-items-center">
                        <span>${a.message} ${mitreBadge}</span>
                        <small class="text-muted">${a.time_local || 'Just now'}</small>
                    </div>`;
                }).join('');
            })
            .catch(err => console.warn('Alerts fetch error:', err));
    }

    function updateTopIPs(srcIPs, dstIPs) {
        const srcList = document.getElementById('top-src-ips');
        if (srcList) {
            if (srcIPs && srcIPs.length > 0) {
                srcList.innerHTML = srcIPs.slice(0, 5).map((ip, i) => 
                    `<li class="list-group-item d-flex justify-content-between align-items-center">
                        <span><i class="fas fa-circle text-success me-2" style="font-size: 0.6rem;"></i>${ip.src_ip || 'Unknown'}</span>
                        <span class="badge bg-primary rounded-pill">${ip.count || 0}</span>
                    </li>`
                ).join('');
            } else {
                srcList.innerHTML = '<li class="list-group-item text-muted text-center">No data</li>';
            }
        }

        const dstList = document.getElementById('top-dst-ips');
        if (dstList) {
            if (dstIPs && dstIPs.length > 0) {
                dstList.innerHTML = dstIPs.slice(0, 5).map((ip, i) => 
                    `<li class="list-group-item d-flex justify-content-between align-items-center">
                        <span><i class="fas fa-circle text-danger me-2" style="font-size: 0.6rem;"></i>${ip.dst_ip || 'Unknown'}</span>
                        <span class="badge bg-danger rounded-pill">${ip.count || 0}</span>
                    </li>`
                ).join('');
            } else {
                dstList.innerHTML = '<li class="list-group-item text-muted text-center">No data</li>';
            }
        }
    }

    function updateProtocolChart(protocolCounts) {
        if (!protocolChartCtx) return;
        
        const labels = protocolCounts.map(p => p.protocol || 'Unknown');
        const counts = protocolCounts.map(p => p.count);

        if (protocolChart) {
            protocolChart.data.labels = labels;
            protocolChart.data.datasets[0].data = counts;
            protocolChart.update();
        } else {
            protocolChart = new Chart(protocolChartCtx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        data: counts,
                        backgroundColor: COLORS.slice(0, labels.length),
                        borderWidth: 2,
                        borderColor: '#ffffff'
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { position: 'bottom' }
                    }
                }
            });
        }
    }

    function fetchStats() {
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => {
                if (data.total_packets > 0) {
                    if (totalPacketsEl) totalPacketsEl.innerText = (data.total_packets || 0).toLocaleString();
                    if (dnsCountEl) dnsCountEl.innerText = (data.dns_count || 0).toLocaleString();
                    if (httpCountEl) httpCountEl.innerText = (data.http_count || 0).toLocaleString();
                    if (httpsCountEl) httpsCountEl.innerText = (data.https_count || 0).toLocaleString();
                    if (tcpCountEl) tcpCountEl.innerText = (data.tcp_count || 0).toLocaleString();
                    if (udpCountEl) udpCountEl.innerText = (data.udp_count || 0).toLocaleString();
                    if (icmpCountEl) icmpCountEl.innerText = (data.icmp_count || 0).toLocaleString();
                    if (arpCountEl) arpCountEl.innerText = (data.arp_count || 0).toLocaleString();
                    updateProtocolChart(data.protocol_counts || []);
                    updateTopIPs(data.top_src_ips, data.top_dst_ips);
                }
            })
            .catch(err => console.warn('Stats fetch error:', err));
    }

    function fetchRecentPackets() {
        fetch('/api/packets?limit=35')
            .then(response => response.json())
            .then(packets => {
                const tbody = document.getElementById('recent-packets-body');
                if (!tbody) return;
                if (!packets || packets.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-3">No packets captured yet. Start capture to begin.</td></tr>`;
                    return;
                }
                tbody.innerHTML = packets.map((p, index) => {
                    const time = p.time_local || new Date(p.timestamp * 1000).toLocaleString();
                    const srcPortStr = p.src_port ? `:${p.src_port}` : '';
                    const dstPortStr = p.dst_port ? `:${p.dst_port}` : '';
                    return `
                        <tr onclick="inspectPacket(${p.id})">
                            <td><span class="badge bg-secondary">${index + 1}</span></td>
                            <td><small>${time}</small></td>
                            <td><span class="badge bg-light text-dark">${p.src_ip || 'N/A'}${srcPortStr}</span></td>
                            <td><span class="badge bg-light text-dark">${p.dst_ip || 'N/A'}${dstPortStr}</span></td>
                            <td><span class="badge bg-info text-white">${p.protocol || 'N/A'}</span></td>
                            <td><span class="badge bg-secondary">${p.length || 0} B</span></td>
                        </tr>
                    `;
                }).join('');
            })
            .catch(err => console.warn('Packets fetch error:', err));
    }

    window.inspectPacket = function(packetId) {
        // Reset modal content
        document.getElementById('inspect-time').innerText = 'Loading...';
        document.getElementById('inspect-proto').innerText = '-';
        document.getElementById('inspect-src').innerText = '-';
        document.getElementById('inspect-dst').innerText = '-';
        document.getElementById('inspect-len').innerText = '-';
        document.getElementById('inspect-layers').innerText = 'Loading packet layers...';
        document.getElementById('inspect-hex').innerText = 'Loading hex dump...';

        // Open modal using Bootstrap API
        const modalEl = document.getElementById('packetInspectorModal');
        const modal = new bootstrap.Modal(modalEl);
        modal.show();

        // Fetch packet details from API
        fetch(`/api/packet/${packetId}`)
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') {
                    const pkt = data.packet;
                    const srcPort = pkt.src_port ? `:${pkt.src_port}` : '';
                    const dstPort = pkt.dst_port ? `:${pkt.dst_port}` : '';

                    document.getElementById('inspect-time').innerText = pkt.time_local || new Date(pkt.timestamp * 1000).toLocaleString();
                    document.getElementById('inspect-proto').innerText = pkt.protocol || 'N/A';
                    document.getElementById('inspect-src').innerText = (pkt.src_ip || 'N/A') + srcPort;
                    document.getElementById('inspect-dst').innerText = (pkt.dst_ip || 'N/A') + dstPort;
                    document.getElementById('inspect-len').innerText = (pkt.length || 0) + ' B';

                    document.getElementById('inspect-layers').innerText = data.layers || 'No layers reconstructed.';
                    document.getElementById('inspect-hex').innerText = data.hex_dump || 'No hex dump available.';
                } else {
                    document.getElementById('inspect-layers').innerText = 'Error loading packet details: ' + data.message;
                }
            })
            .catch(err => {
                document.getElementById('inspect-layers').innerText = 'Error fetching packet details: ' + err.message;
            });
    };

    let userDismissedError = false;
    let currentCanCapture = true;
    let isSimulationMode = false;

    function showCaptureError(msg) {
        if (userDismissedError) return;
        const errorAlert = document.getElementById('capture-error-alert');
        const errorMsg = document.getElementById('capture-error-msg');
        if (errorAlert && errorMsg) {
            errorMsg.innerText = msg;
            errorAlert.classList.remove('d-none');
        }
    }

    function hideCaptureError() {
        const errorAlert = document.getElementById('capture-error-alert');
        if (errorAlert) {
            errorAlert.classList.add('d-none');
        }
    }

    // Dismiss button on capture error alert
    document.querySelector('#capture-error-alert .btn-close')?.addEventListener('click', function() {
        userDismissedError = true;
        hideCaptureError();
        fetch('/api/capture/clear-error', { method: 'POST' }).catch(() => {});
    });

    function updateCaptureStatus(isRunning, canCapture = true, message = '', simulation = false) {
        if (!captureStatusEl) return;
        if (isRunning) {
            isSimulationMode = simulation;
            captureStatusEl.innerText = '🟢 Running';
            captureStatusEl.className = 'badge-status running';
            captureStatusEl.title = simulation ? 'Live simulated SOC traffic active' : 'Live packet capture active';
        } else if (canCapture === false) {
            isSimulationMode = false;
            captureStatusEl.innerText = '☁️ Cloud Mode';
            captureStatusEl.className = 'badge-status stopped';
            captureStatusEl.title = message || 'Container environment: Live Traffic Simulator ready, or use Remote Agent.';
        } else {
            isSimulationMode = false;
            captureStatusEl.innerText = '🔴 Stopped';
            captureStatusEl.className = 'badge-status stopped';
            captureStatusEl.title = 'Packet capture idle';
        }
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

    const interfaceSelectEl = document.getElementById('interface-select');

    function populateInterfaces(canCapture = true) {
        if (!interfaceSelectEl) return;
        fetch('/api/interfaces')
            .then(res => res.json())
            .then(data => {
                interfaceSelectEl.innerHTML = '<option value="">Auto-Detect (Local Live Sniffer)</option>';
                data.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface.name;
                    const ipStr = iface.ip ? ` - ${iface.ip}` : '';
                    const descStr = iface.description ? ` (${iface.description})` : '';
                    option.innerText = `${iface.type || 'Interface'}: ${iface.name}${ipStr}${descStr}`;
                    interfaceSelectEl.appendChild(option);
                });
            })
            .catch(err => console.warn('Error loading interfaces:', err));
    }

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
                tbody.innerHTML = data.map((item, index) => {
                    const packets = item.packets || item.count || 0;
                    return `
                        <tr>
                            <td>#${index + 1}</td>
                            <td><span class="badge bg-dark">${item.ip || 'Unknown'}</span></td>
                            <td>${packets.toLocaleString()}</td>
                            <td>${formatBytes(item.bytes || 0)}</td>
                        </tr>
                    `;
                }).join('');
            })
            .catch(err => {
                console.warn('Top talkers error:', err);
                const tbody = document.getElementById('top-talkers-body');
                if (tbody) tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">Error loading data</td></tr>`;
            });
    }

    function loadSystemInfo() {
        fetch('/api/system/info')
            .then(res => res.json())
            .then(data => {
                const osEl = document.getElementById('system-os');
                const pyEl = document.getElementById('system-python');
                const dbSizeEl = document.getElementById('system-db-size');
                
                if (osEl) osEl.innerText = data.os || 'Unknown';
                if (pyEl) pyEl.innerText = data.python || 'Unknown';
                
                if (dbSizeEl && data.db_size !== undefined) {
                    const size = data.db_size;
                    if (size < 1024) {
                        dbSizeEl.innerText = size + ' B';
                    } else if (size < 1024 * 1024) {
                        dbSizeEl.innerText = (size / 1024).toFixed(1) + ' KB';
                    } else {
                        dbSizeEl.innerText = (size / (1024 * 1024)).toFixed(1) + ' MB';
                    }
                }
            })
            .catch(err => console.warn('System info error:', err));
    }

    function formatBytes(bytes) {
        if (bytes === 0 || !bytes) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    document.getElementById('start-capture')?.addEventListener('click', function() {
        console.log('Start button clicked!');
        userDismissedError = false;
        hideCaptureError();
        
        const selectedInterface = interfaceSelectEl ? interfaceSelectEl.value : '';
        const isSim = (selectedInterface === 'simulate' || currentCanCapture === false);
        const endpoint = isSim ? '/api/simulation/start' : '/api/capture/start';
        const payload = isSim ? {} : { interface: selectedInterface };
        
        fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        })
        .then(async response => {
            const data = await response.json().catch(() => ({}));
            if (!response.ok || data.status === 'error') {
                const msg = data.message || `HTTP ${response.status}: Failed to start capture`;
                throw new Error(msg);
            }
            return data;
        })
        .then(data => {
            console.log('Start response:', data);
            hideCaptureError();
            currentSessionId = data.session_id;
            updateCaptureStatus(true, currentCanCapture, '', isSim || data.mode === 'simulation');
            
            document.dispatchEvent(new CustomEvent('captureStarted', {
                detail: { sessionId: currentSessionId }
            }));
            
            if (!liveInterval) {
                liveInterval = setInterval(fetchLiveStats, 2000);
            }
            fetchLiveStats();
            updateTopTalkers();
        })
        .catch(err => {
            console.error('Start error:', err);
            updateCaptureStatus(false, currentCanCapture);
            showCaptureError(err.message || 'Error starting capture');
        });
    });

    document.getElementById('stop-capture')?.addEventListener('click', function() {
        console.log('Stop button clicked!');
        const endpoint = isSimulationMode ? '/api/simulation/stop' : '/api/capture/stop';
        fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        })
        .then(async response => {
            const data = await response.json().catch(() => ({}));
            if (!response.ok || data.status === 'error') {
                const msg = data.message || `HTTP ${response.status}: Failed to stop capture`;
                throw new Error(msg);
            }
            return data;
        })
        .then(data => {
            console.log('Stop response:', data);
            
            document.dispatchEvent(new CustomEvent('captureStopped', {
                detail: { sessionId: data.session_id }
            }));
            
            if (liveInterval) {
                clearInterval(liveInterval);
                liveInterval = null;
            }
            updateCaptureStatus(false, currentCanCapture);
            fetchStats();
            fetchRecentPackets();
            fetchRecentAlerts();
            updateTopTalkers();
        })
        .catch(err => {
            console.error('Stop error:', err);
            showCaptureError(err.message || 'Error stopping capture');
        });
    });

    document.getElementById('btn-demo-data')?.addEventListener('click', function() {
        const btn = this;
        const origHtml = btn.innerHTML;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating...';
        btn.disabled = true;

        fetch('/api/demo/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ count: 120 })
        })
        .then(res => res.json())
        .then(resData => {
            btn.innerHTML = '<i class="fas fa-check"></i> Done!';
            setTimeout(() => {
                btn.innerHTML = origHtml;
                btn.disabled = false;
            }, 1200);

            fetchLiveStats();
            fetchRecentPackets();
            fetchRecentAlerts();
            updateTopTalkers();
        })
        .catch(err => {
            console.error('Demo generation error:', err);
            btn.innerHTML = origHtml;
            btn.disabled = false;
            alert('Error generating demo data: ' + err.message);
        });
    });

    function updateCaptureStatusFromAPI() {
        fetch('/api/capture/status')
            .then(response => response.json())
            .then(data => {
                currentCanCapture = data.can_capture;
                updateCaptureStatus(data.running, data.can_capture, data.capture_message, data.simulation);
                if (data.running && !liveInterval) {
                    liveInterval = setInterval(fetchLiveStats, 2000);
                    fetchLiveStats();
                } else if (!data.running && liveInterval) {
                    clearInterval(liveInterval);
                    liveInterval = null;
                }

                if (!data.running) {
                    fetchStats();
                    fetchRecentAlerts();
                }

                if (data.last_error && !data.running && !userDismissedError) {
                    showCaptureError(data.last_error);
                }
            })
            .catch(() => {});
    }

    // 🔥 Initial load
    fetch('/api/capture/status')
        .then(response => response.json())
        .then(data => {
            currentCanCapture = data.can_capture;
            populateInterfaces(data.can_capture);
            loadSystemInfo();
            updateTopTalkers();
            if (typeof window.fetchDNSQueries === 'function') window.fetchDNSQueries();
            updateCaptureStatus(data.running, data.can_capture, data.capture_message, data.simulation);
            if (data.running) {
                liveInterval = setInterval(fetchLiveStats, 2000);
                fetchLiveStats();
            } else {
                fetchStats();
            }
            if (data.last_error && !data.running && !userDismissedError) {
                showCaptureError(data.last_error);
            }
        })
        .catch(() => {
            populateInterfaces(true);
            loadSystemInfo();
            updateTopTalkers();
            if (typeof window.fetchDNSQueries === 'function') window.fetchDNSQueries();
            fetchStats();
        });

    fetchRecentPackets();
    fetchRecentAlerts();
    if (typeof window.fetchDNSQueries === 'function') window.fetchDNSQueries();
    
    // Auto-refreshes
    setInterval(fetchRecentPackets, 5000);
    setInterval(updateCaptureStatusFromAPI, 3000);
    setInterval(updateTopTalkers, 5000);
});