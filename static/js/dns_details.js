document.addEventListener('DOMContentLoaded', function() {
    let dnsInterval = null;

    function fetchDNSDetails() {
        fetch('/api/dns/live')
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') {
                    updateDNSTable(data.queries);
                    updateStats(data);
                }
            })
            .catch(err => console.warn('DNS details error:', err));
    }

    function updateDNSTable(queries) {
        const tbody = document.getElementById('dns-details-body');
        if (!tbody) return;

        if (!queries || queries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted">No DNS data yet</td></tr>';
            return;
        }

        tbody.innerHTML = queries.slice(0, 50).map(q => {
            const time = q.time_local || new Date(q.timestamp * 1000).toLocaleString();
            const srcIp = q.src_ip || 'N/A';
            const dstIp = q.dst_ip || 'N/A';
            const domain = q.domain || 'Unknown';
            const queryType = q.query_type || 'A';
            const isResponse = q.is_response ? '✅ Yes' : '❌ No';
            const ttl = q.ttl || '-';
            const rcode = q.rcode || '-';
            
            // Parse answer records
            let answers = '-';
            if (q.answer_records && q.answer_records.length > 0) {
                answers = q.answer_records.map(a => 
                    `${a.type}: ${a.rdata} (TTL: ${a.ttl})`
                ).join('<br>');
            }
            
            const responseBadge = q.is_response ? 'bg-success' : 'bg-warning';
            
            return `
                <tr>
                    <td><small>${time}</small></td>
                    <td><span class="badge bg-light text-dark">${srcIp}</span></td>
                    <td><span class="badge bg-light text-dark">${dstIp}</span></td>
                    <td><span class="badge bg-info text-white">${domain}</span></td>
                    <td><span class="badge bg-secondary">${queryType}</span></td>
                    <td><span class="badge ${responseBadge}">${isResponse}</span></td>
                    <td><span class="badge bg-dark">${ttl}</span></td>
                    <td><span class="badge bg-secondary">${rcode}</span></td>
                    <td style="font-size: 0.7rem;">${answers}</td>
                </tr>
            `;
        }).join('');
    }

    function updateStats(data) {
        document.getElementById('dns-total').innerText = data.count || 0;
        document.getElementById('dns-session').innerText = data.session_id || '-';
        document.getElementById('dns-count-badge').innerText = data.count || 0;
        
        // Count responses
        const responses = data.queries ? data.queries.filter(q => q.is_response).length : 0;
        document.getElementById('dns-responses').innerText = responses;
        
        // Count unique domains
        if (data.queries) {
            const unique = new Set(data.queries.map(q => q.domain)).size;
            document.getElementById('dns-unique').innerText = unique;
        }
    }

    function startLiveUpdates() {
        if (dnsInterval) clearInterval(dnsInterval);
        fetchDNSDetails();
        dnsInterval = setInterval(fetchDNSDetails, 3000);
    }

    function checkCaptureStatus() {
        fetch('/api/capture/status')
            .then(res => res.json())
            .then(data => {
                if (data.running) {
                    startLiveUpdates();
                }
            })
            .catch(() => {});
    }

    fetchDNSDetails();
    checkCaptureStatus();
    setInterval(checkCaptureStatus, 10000);
});