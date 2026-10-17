// ============================================
// 🔍 DNS MONITOR - Wireshark Style
// ============================================

document.addEventListener('DOMContentLoaded', function() {
    let dnsInterval = null;
    let isCaptureRunning = false;

    function fetchDNSQueries() {
        console.log('Fetching DNS queries...');
        fetch('/api/dns/live')
            .then(response => {
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                return response.json();
            })
            .then(data => {
                console.log('DNS data:', data);
                if (data.status === 'success') {
                    updateDNSTable(data.queries);
                    updateDNSBadge(data.count);
                }
            })
            .catch(err => {
                console.error('DNS fetch error:', err);
            });
    }

    function updateDNSTable(queries) {
        const tbody = document.getElementById('dns-body');
        if (!tbody) return;

        if (!queries || queries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No DNS queries yet</td></tr>';
            return;
        }

        const displayQueries = queries.slice(0, 30);
        
        tbody.innerHTML = displayQueries.map((q, index) => {
            const time = q.time_local || new Date(q.timestamp * 1000).toLocaleString();
            const srcIp = q.src_ip || 'N/A';
            const domain = q.domain || 'Unknown';
            const queryType = q.query_type || 'A';
            const ttl = q.ttl || '-';
            
            // Status based on response
            let status = 'Query';
            let statusBadge = 'bg-warning';
            if (q.is_response) {
                status = 'Response';
                statusBadge = 'bg-success';
            }
            
            // Response details
            let responseDetails = '-';
            if (q.answer_records && q.answer_records.length > 0) {
                responseDetails = q.answer_records.map(a => {
                    return `${a.type}: ${a.rdata}`;
                }).join(', ');
                if (responseDetails.length > 50) {
                    responseDetails = responseDetails.substring(0, 50) + '...';
                }
            }
            
            // RCODE
            const rcode = q.rcode || '-';
            const rcodeBadge = q.rcode === 'No Error' ? 'bg-success' : 'bg-danger';
            
            const isDashboard = document.querySelector('#dns-table thead th') !== null;
            if (isDashboard) {
                return `
                    <tr>
                        <td><small>${time}</small></td>
                        <td><span class="badge bg-light text-dark">${srcIp}</span></td>
                        <td><span class="badge bg-info text-white" style="font-size:0.7rem;">${domain}</span></td>
                    </tr>
                `;
            }

            return `
                <tr>
                    <td><span class="badge bg-secondary">${index + 1}</span></td>
                    <td><small>${time}</small></td>
                    <td><span class="badge bg-light text-dark">${srcIp}</span></td>
                    <td><span class="badge bg-info text-white" style="font-size:0.7rem;">${domain}</span></td>
                    <td><span class="badge bg-secondary">${queryType}</span></td>
                    <td><span class="badge bg-dark">${ttl}</span></td>
                    <td><span class="badge ${statusBadge}">${status}</span></td>
                    <td style="font-size: 0.6rem;">
                        <span class="badge ${rcodeBadge}">${rcode}</span>
                        ${responseDetails !== '-' ? `<br><small class="text-muted">${responseDetails}</small>` : ''}
                    </td>
                </tr>
            `;
        }).join('');
    }

    function updateDNSBadge(count) {
        const badge = document.getElementById('dns-count-badge');
        if (badge) {
            badge.innerText = count || 0;
            
            // Color based on count
            if (count > 50) {
                badge.className = 'badge bg-danger ms-2';
            } else if (count > 20) {
                badge.className = 'badge bg-warning ms-2';
            } else {
                badge.className = 'badge bg-info ms-2';
            }
        }
    }

    function startDNSMonitoring() {
        if (dnsInterval) clearInterval(dnsInterval);
        fetchDNSQueries();
        dnsInterval = setInterval(fetchDNSQueries, 2000);
        console.log('DNS monitoring started');
    }

    function stopDNSMonitoring() {
        if (dnsInterval) {
            clearInterval(dnsInterval);
            dnsInterval = null;
            console.log('DNS monitoring stopped');
        }
    }

    document.addEventListener('captureStarted', function(e) {
        console.log('✅ Capture started, starting DNS monitor');
        isCaptureRunning = true;
        startDNSMonitoring();
    });

    document.addEventListener('captureStopped', function(e) {
        console.log('❌ Capture stopped, stopping DNS monitor');
        isCaptureRunning = false;
        stopDNSMonitoring();
    });

    function checkCaptureStatus() {
        fetch('/api/capture/status')
            .then(response => response.json())
            .then(data => {
                if (data.running) {
                    if (!isCaptureRunning) {
                        isCaptureRunning = true;
                        startDNSMonitoring();
                    }
                } else {
                    if (isCaptureRunning) {
                        isCaptureRunning = false;
                        stopDNSMonitoring();
                    }
                }
            })
            .catch(() => {});
    }

    fetchDNSQueries();
    checkCaptureStatus();
    setInterval(checkCaptureStatus, 10000);
    console.log('DNS Monitor initialized');
});