document.addEventListener('DOMContentLoaded', function() {
    // ============================================
    // 📊 CHART INSTANCES
    // ============================================
    let timelineChart = null;
    let protocolPie = null;
    let topSrcChart = null;
    let topDstChart = null;
    let topPortsChart = null;
    
    let updateInterval = null;
    let lastPacketCount = 0;
    let lastUpdateTime = Date.now();

    // ============================================
    // 🎨 COLOR PALETTE
    // ============================================
    const COLORS = {
        blue: '#3b82f6',
        green: '#22c55e',
        yellow: '#f59e0b',
        red: '#ef4444',
        purple: '#8b5cf6',
        pink: '#ec4899',
        teal: '#14b8a6',
        orange: '#f97316',
        cyan: '#06b6d4',
        gray: '#6b7280'
    };

    const COLOR_ARRAY = [
        '#3b82f6', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6',
        '#ec4899', '#14b8a6', '#f97316', '#06b6d4', '#6b7280'
    ];

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

    function formatBandwidth(bytesPerSecond) {
        if (bytesPerSecond < 1024) return bytesPerSecond.toFixed(0) + ' B/s';
        if (bytesPerSecond < 1024 * 1024) return (bytesPerSecond / 1024).toFixed(1) + ' KB/s';
        return (bytesPerSecond / (1024 * 1024)).toFixed(1) + ' MB/s';
    }

    // ============================================
    // 🔄 FETCH VISUALIZATION DATA
    // ============================================
    function fetchVisualizationData() {
        const now = Date.now();
        const elapsed = (now - lastUpdateTime) / 1000;
        
        fetch('/api/live-stats')
            .then(res => {
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                return res.json();
            })
            .then(data => {
                // Update stats
                document.getElementById('vis-total-packets').innerText = (data.total_packets || 0).toLocaleString();
                document.getElementById('vis-pps').innerText = Math.round(data.packets_per_second || 0);
                document.getElementById('vis-bandwidth').innerText = formatBandwidth(data.bandwidth || 0);
                
                // Active TCP connections
                let tcpCount = data.tcp_count || data.tcp_packets || 0;
                document.getElementById('vis-active-tcp').innerText = tcpCount;
                
                lastPacketCount = data.total_packets || 0;
                lastUpdateTime = now;
                
                // Update charts
                updateTimelineChart(data);
                updateProtocolPie(data);
                updateTopCharts(data);
                
                // Update time
                document.getElementById('vis-update-time').innerText = new Date().toLocaleTimeString();
            })
            .catch(err => {
                console.warn('Visualization data error:', err);
            });
    }

    // ============================================
    // 📈 TRAFFIC TIMELINE CHART
    // ============================================
    function updateTimelineChart(data) {
        const ctx = document.getElementById('timeline-chart');
        if (!ctx) return;

        // Get timeline data from API
        fetch('/api/traffic/timeline?interval=10')
            .then(res => res.json())
            .then(timelineData => {
                if (!timelineData || timelineData.length === 0) {
                    if (timelineChart) {
                        timelineChart.data.labels = ['No Data'];
                        timelineChart.data.datasets[0].data = [0];
                        timelineChart.update();
                    }
                    return;
                }

                const labels = timelineData.map(d => {
                    const date = new Date(d.time_bucket * 1000);
                    return date.toLocaleTimeString('en-IN', { hour12: false, hour: '2-digit', minute: '2-digit' });
                });
                const values = timelineData.map(d => d.count || 0);

                if (timelineChart) {
                    timelineChart.data.labels = labels;
                    timelineChart.data.datasets[0].data = values;
                    timelineChart.update();
                } else {
                    timelineChart = new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: labels,
                            datasets: [{
                                label: 'Packets',
                                data: values,
                                borderColor: '#3b82f6',
                                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                                fill: true,
                                tension: 0.4,
                                pointRadius: 2,
                                pointBackgroundColor: '#3b82f6'
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: { display: false }
                            },
                            scales: {
                                x: {
                                    grid: { display: false },
                                    ticks: { maxTicksLimit: 10 }
                                },
                                y: {
                                    beginAtZero: true,
                                    grid: { color: 'rgba(0,0,0,0.05)' }
                                }
                            }
                        }
                    });
                }
            })
            .catch(err => console.warn('Timeline error:', err));
    }

    // ============================================
    // 🥧 PROTOCOL DISTRIBUTION PIE
    // ============================================
    function updateProtocolPie(data) {
        const ctx = document.getElementById('protocol-pie');
        if (!ctx) return;

        const protoCounts = data.protocol_counts || [];
        if (protoCounts.length === 0) {
            if (protocolPie) {
                protocolPie.data.labels = ['No Data'];
                protocolPie.data.datasets[0].data = [1];
                protocolPie.update();
            }
            return;
        }

        const sorted = protoCounts.sort((a, b) => b.count - a.count);
        const labels = sorted.slice(0, 8).map(p => p.protocol || 'Unknown');
        const values = sorted.slice(0, 8).map(p => p.count);
        
        // If more than 8, group others
        if (sorted.length > 8) {
            const otherCount = sorted.slice(8).reduce((sum, p) => sum + p.count, 0);
            labels.push('Others');
            values.push(otherCount);
        }

        if (protocolPie) {
            protocolPie.data.labels = labels;
            protocolPie.data.datasets[0].data = values;
            protocolPie.update();
        } else {
            protocolPie = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        data: values,
                        backgroundColor: COLOR_ARRAY.slice(0, labels.length),
                        borderWidth: 2,
                        borderColor: '#ffffff'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { font: { size: 10 }, boxWidth: 12 }
                        }
                    }
                }
            });
        }
    }

    // ============================================
    // 📊 TOP CHARTS (Bar Charts)
    // ============================================
    function updateTopCharts(data) {
        // Top Source IPs
        const srcIps = data.top_src_ips || [];
        updateBarChart('top-src-chart', srcIps.slice(0, 8), 'src_ip', 'Source IP', '#22c55e');

        // Top Destination IPs
        const dstIps = data.top_dst_ips || [];
        updateBarChart('top-dst-chart', dstIps.slice(0, 8), 'dst_ip', 'Destination IP', '#ef4444');

        // Top Ports (from TCP/UDP packets)
        updateTopPorts();
    }

    function updateBarChart(canvasId, data, key, label, color) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return;

        if (!data || data.length === 0) {
            if (window[canvasId + 'Chart']) {
                window[canvasId + 'Chart'].data.labels = ['No Data'];
                window[canvasId + 'Chart'].data.datasets[0].data = [0];
                window[canvasId + 'Chart'].update();
            }
            return;
        }

        const labels = data.map(d => d[key] || 'Unknown');
        const values = data.map(d => d.count || 0);

        const chartKey = canvasId + 'Chart';
        if (window[chartKey]) {
            window[chartKey].data.labels = labels;
            window[chartKey].data.datasets[0].data = values;
            window[chartKey].update();
        } else {
            window[chartKey] = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [{
                        label: label,
                        data: values,
                        backgroundColor: color + '80',
                        borderColor: color,
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: { font: { size: 8 } }
                        },
                        y: {
                            beginAtZero: true,
                            grid: { color: 'rgba(0,0,0,0.05)' }
                        }
                    }
                }
            });
        }
    }

    // ============================================
    // 🔌 TOP PORTS
    // ============================================
    function updateTopPorts() {
        const ctx = document.getElementById('top-ports-chart');
        if (!ctx) return;

        fetch('/api/packets?limit=100')
            .then(res => res.json())
            .then(packets => {
                if (!packets || packets.length === 0) {
                    if (topPortsChart) {
                        topPortsChart.data.labels = ['No Data'];
                        topPortsChart.data.datasets[0].data = [0];
                        topPortsChart.update();
                    }
                    return;
                }

                const portCounts = {};
                packets.forEach(p => {
                    const port = p.dst_port || p.src_port;
                    if (port && port > 0 && port < 65535) {
                        portCounts[port] = (portCounts[port] || 0) + 1;
                    }
                });

                const sorted = Object.entries(portCounts)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 8);

                const labels = sorted.map(([port]) => port);
                const values = sorted.map(([, count]) => count);

                if (topPortsChart) {
                    topPortsChart.data.labels = labels;
                    topPortsChart.data.datasets[0].data = values;
                    topPortsChart.update();
                } else {
                    topPortsChart = new Chart(ctx, {
                        type: 'bar',
                        data: {
                            labels: labels,
                            datasets: [{
                                label: 'Packets',
                                data: values,
                                backgroundColor: '#8b5cf6' + '80',
                                borderColor: '#8b5cf6',
                                borderWidth: 1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: { display: false }
                            },
                            scales: {
                                x: {
                                    grid: { display: false },
                                    ticks: { font: { size: 8 } }
                                },
                                y: {
                                    beginAtZero: true,
                                    grid: { color: 'rgba(0,0,0,0.05)' }
                                }
                            }
                        }
                    });
                }
            })
            .catch(err => console.warn('Top ports error:', err));
    }

    // ============================================
    // 🔄 START/STOP AUTO-UPDATE
    // ============================================
    function startLiveUpdates() {
        if (updateInterval) clearInterval(updateInterval);
        
        // Initial fetch
        fetchVisualizationData();
        
        // Update every 2 seconds
        updateInterval = setInterval(fetchVisualizationData, 2000);
        
        document.getElementById('vis-live-status').innerText = '🟢 Live';
        console.log('Visualizations live updates started');
    }

    function stopLiveUpdates() {
        if (updateInterval) {
            clearInterval(updateInterval);
            updateInterval = null;
        }
        document.getElementById('vis-live-status').innerText = '🔴 Stopped';
        console.log('Visualizations live updates stopped');
    }

    // ============================================
    // 🔍 CHECK CAPTURE STATUS
    // ============================================
    function checkCaptureStatus() {
        fetch('/api/capture/status')
            .then(response => response.json())
            .then(data => {
                if (data.running) {
                    startLiveUpdates();
                } else {
                    stopLiveUpdates();
                    // Show last data
                    fetchVisualizationData();
                }
            })
            .catch(() => {
                startLiveUpdates();
            });
    }

    // ============================================
    // 🔄 LISTEN FOR CAPTURE EVENTS
    // ============================================
    document.addEventListener('captureStarted', function(e) {
        console.log('✅ Capture started, starting visualizations live updates');
        startLiveUpdates();
    });

    document.addEventListener('captureStopped', function(e) {
        console.log('❌ Capture stopped, stopping visualizations live updates');
        stopLiveUpdates();
    });

    // ============================================
    // 🔄 INITIALIZE
    // ============================================
    // Initial fetch
    fetchVisualizationData();
    checkCaptureStatus();
    
    // Also check status every 10 seconds
    setInterval(checkCaptureStatus, 10000);

    console.log('Visualizations page initialized');
});