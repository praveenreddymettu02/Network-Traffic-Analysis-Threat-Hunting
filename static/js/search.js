// ============================================
// 🔍 SEARCH PACKETS - JavaScript
// ============================================

function searchPackets() {
    const ip = document.getElementById('search-ip').value.trim();
    const domain = document.getElementById('search-domain').value.trim();
    const searchTerm = ip || domain;
    
    if (!searchTerm) {
        document.getElementById('search-results').innerHTML = 
            '<p class="text-warning text-center">Please enter an IP or domain to search</p>';
        return;
    }
    
    const resultsDiv = document.getElementById('search-results');
    resultsDiv.innerHTML = '<div class="text-center"><i class="fas fa-spinner fa-spin"></i> Searching...</div>';
    
    fetch(`/api/packets/search?ip=${encodeURIComponent(ip)}&domain=${encodeURIComponent(domain)}`)
        .then(res => res.json())
        .then(data => {
            if (data.error) {
                resultsDiv.innerHTML = `<p class="text-danger text-center">❌ ${data.error}</p>`;
                return;
            }
            
            if (!data || data.length === 0) {
                resultsDiv.innerHTML = `<p class="text-muted text-center">No packets found for "${searchTerm}"</p>`;
                return;
            }
            
            let html = `
                <div class="table-responsive">
                    <table class="table table-theme table-sm" style="font-size: 0.75rem;">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Source IP</th>
                                <th>Destination IP</th>
                                <th>Protocol</th>
                                <th>Size</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            
            data.forEach(p => {
                const time = p.time_local || new Date(p.timestamp * 1000).toLocaleString();
                html += `
                    <tr>
                        <td>${time}</td>
                        <td><span class="badge bg-light text-dark">${p.src_ip || 'N/A'}</span></td>
                        <td><span class="badge bg-light text-dark">${p.dst_ip || 'N/A'}</span></td>
                        <td><span class="badge bg-info text-white">${p.protocol || 'N/A'}</span></td>
                        <td>${p.length || 0} B</td>
                    </tr>
                `;
            });
            
            html += `
                        </tbody>
                    </table>
                </div>
                <p class="text-muted small">Found ${data.length} packets</p>
            `;
            
            resultsDiv.innerHTML = html;
        })
        .catch(err => {
            console.error('Search error:', err);
            resultsDiv.innerHTML = `<p class="text-danger text-center">❌ Error: ${err.message}</p>`;
        });
}

// Enter key support
document.addEventListener('DOMContentLoaded', function() {
    const ipInput = document.getElementById('search-ip');
    const domainInput = document.getElementById('search-domain');
    
    if (ipInput) {
        ipInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') searchPackets();
        });
    }
    if (domainInput) {
        domainInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') searchPackets();
        });
    }
});