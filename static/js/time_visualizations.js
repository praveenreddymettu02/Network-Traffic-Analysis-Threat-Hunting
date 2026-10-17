document.addEventListener('DOMContentLoaded', function() {
    let currentData = [];
    let updateInterval = null;

    const buttons = document.querySelectorAll('#time-range-buttons .btn');
    const timelineDiv = document.getElementById('timeline-chart');

    if (typeof Plotly === 'undefined') {
        timelineDiv.innerHTML = '<div class="alert alert-warning">⚠️ Plotly library not loaded.</div>';
        return;
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // ============================================
    // 🔥 FETCH TIME DATA WITH AUTO-UPDATE
    // ============================================
    function fetchTimeData(range) {
        fetch(`/api/traffic/${range}`)
            .then(res => {
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                return res.json();
            })
            .then(data => {
                currentData = data;
                updateTimeline(data, range);
                updateStats(data, range);
                updateTable(data, range);
            })
            .catch(err => {
                console.error('Error:', err);
                timelineDiv.innerHTML = `<div class="alert alert-danger py-2">❌ ${err.message}</div>`;
            });
    }

    // ============================================
    // 📊 UPDATE TIMELINE
    // ============================================
    function updateTimeline(data, range) {
        if (!data || data.length === 0) {
            timelineDiv.innerHTML = `<div class="text-muted text-center py-3">No ${range} data available.</div>`;
            return;
        }

        let labels = [];
        let counts = [];
        
        data.forEach(d => {
            let label = '';
            if (range === 'hourly') {
                label = d.hour_label || d.time_bucket || 'Unknown';
            } else if (range === 'daily') {
                label = d.date || 'Unknown';
            } else if (range === 'weekly') {
                label = `${d.start_date} - ${d.end_date}`;
            } else if (range === 'monthly') {
                label = d.month || 'Unknown';
            }
            labels.push(label);
            counts.push(d.count || 0);
        });

        const trace = {
            x: labels,
            y: counts,
            type: 'bar',
            marker: { 
                color: '#3b82f6', 
                opacity: 0.8,
                line: { color: '#2563eb', width: 1 }
            },
            hovertemplate: '<b>%{x}</b><br>Packets: %{y}<extra></extra>'
        };

        const layout = {
            paper_bgcolor: 'rgba(255,255,255,0)',
            plot_bgcolor: 'rgba(255,255,255,0)',
            margin: { l: 50, r: 15, t: 10, b: 60 },
            xaxis: { 
                tickangle: -45,
                tickfont: { size: 9 },
                gridcolor: '#e5e7eb',
                tickmode: 'auto',
                nticks: 12
            },
            yaxis: { 
                title: 'Packets',
                tickfont: { size: 9 },
                gridcolor: '#e5e7eb'
            },
            hovermode: 'x unified',
            showlegend: false,
            font: { size: 10 },
            height: 300
        };

        Plotly.react('timeline-chart', [trace], layout, { 
            responsive: true, 
            displayModeBar: false 
        });
    }

    // ============================================
    // 📊 UPDATE STATS
    // ============================================
    function updateStats(data, range) {
        if (!data || data.length === 0) return;

        const totalPackets = data.reduce((sum, d) => sum + (d.count || 0), 0);
        const totalBytes = data.reduce((sum, d) => sum + (d.bytes || 0), 0);
        const uniqueHosts = data.reduce((sum, d) => sum + (d.unique_hosts || 0), 0);

        const packetsEl = document.getElementById('total-packets-stats');
        const bytesEl = document.getElementById('total-bytes-stats');
        const hostsEl = document.getElementById('unique-hosts-stats');

        if (packetsEl) packetsEl.innerText = totalPackets.toLocaleString();
        if (bytesEl) bytesEl.innerText = formatBytes(totalBytes);
        if (hostsEl) hostsEl.innerText = uniqueHosts || 'N/A';
    }

    // ============================================
    // 📊 UPDATE TABLE
    // ============================================
    function updateTable(data, range) {
        const tbody = document.getElementById('traffic-summary-body');
        if (!tbody) return;
        
        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No data available</td></tr>';
            return;
        }

        const showData = data.slice(0, 10);
        tbody.innerHTML = showData.map(d => {
            let period = '';
            if (range === 'hourly') {
                period = d.time_bucket || d.hour_label || 'Unknown';
            } else if (range === 'daily') {
                period = d.date || 'Unknown';
            } else if (range === 'weekly') {
                period = `${d.start_date} - ${d.end_date}`;
            } else if (range === 'monthly') {
                period = d.month || 'Unknown';
            }
            const avg = d.count ? Math.round(d.count / 7) : 0;
            return `<tr>
                <td><span class="badge bg-info" style="font-size:0.7rem;">${period}</span></td>
                <td>${(d.count || 0).toLocaleString()}</td>
                <td>${formatBytes(d.bytes || 0)}</td>
                <td>${d.unique_hosts || 'N/A'}</td>
                <td>${avg.toLocaleString()}</td>
            </tr>`;
        }).join('');
    }

    // ============================================
    // 🔄 START AUTO-UPDATE
    // ============================================
    function startAutoUpdate(range) {
        if (updateInterval) {
            clearInterval(updateInterval);
        }
        // Fetch immediately
        fetchTimeData(range);
        // Then every 10 seconds
        updateInterval = setInterval(() => {
            fetchTimeData(range);
        }, 10000);
        console.log(`Auto-update started for ${range} (every 10s)`);
    }

    function stopAutoUpdate() {
        if (updateInterval) {
            clearInterval(updateInterval);
            updateInterval = null;
            console.log('Auto-update stopped');
        }
    }

    // ============================================
    // 🔘 BUTTON HANDLERS
    // ============================================
    buttons.forEach(btn => {
        btn.addEventListener('click', function() {
            buttons.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            const range = this.dataset.range;
            startAutoUpdate(range);
        });
    });

    // ============================================
    // 🔍 CHECK CAPTURE STATUS
    // ============================================
    function checkCaptureStatus() {
        fetch('/api/capture/status')
            .then(res => res.json())
            .then(data => {
                if (data.running) {
                    const activeBtn = document.querySelector('#time-range-buttons .btn.active');
                    const range = activeBtn ? activeBtn.dataset.range : 'hourly';
                    startAutoUpdate(range);
                } else {
                    stopAutoUpdate();
                }
            })
            .catch(() => {
                // Fallback: start updates anyway
                const activeBtn = document.querySelector('#time-range-buttons .btn.active');
                const range = activeBtn ? activeBtn.dataset.range : 'hourly';
                startAutoUpdate(range);
            });
    }

    // ============================================
    // 🔄 INITIALIZE
    // ============================================
    // Load default data
    const defaultRange = 'hourly';
    // Mark hourly as active
    buttons.forEach(btn => {
        if (btn.dataset.range === defaultRange) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });
    
    checkCaptureStatus();

    // Also check status every 15 seconds
    setInterval(checkCaptureStatus, 15000);

    console.log('Time visualizations auto-update initialized');
});