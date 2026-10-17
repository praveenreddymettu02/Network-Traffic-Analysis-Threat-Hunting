// ============================================
// 📋 EXPORT FUNCTIONS - CSV, PDF, JSON
// ============================================

// ============================================
// 📊 EXPORT CSV
// ============================================
function exportCSV() {
    console.log('Exporting CSV...');
    
    fetch('/api/top/talkers')
        .then(res => res.json())
        .then(data => {
            if (!data || data.length === 0) {
                alert('No data to export');
                return;
            }
            
            // Create CSV content
            let csv = 'Rank,IP Address,Packets,Bandwidth (Bytes)\n';
            data.forEach((item, index) => {
                csv += `${index + 1},${item.ip},${item.packets},${item.bytes}\n`;
            });
            
            // Add timestamp
            csv += `\nExported on: ${new Date().toLocaleString()}`;
            
            // Download
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `top_talkers_${new Date().toISOString().slice(0,10)}.csv`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            console.log('CSV exported successfully');
        })
        .catch(err => {
            console.error('Export CSV error:', err);
            alert('Error exporting CSV: ' + err.message);
        });
}

// ============================================
// 📄 EXPORT PDF (Using browser print)
// ============================================
function exportPDF() {
    console.log('Exporting PDF...');
    
    // Get table data
    const table = document.getElementById('top-talkers-table');
    if (!table) {
        alert('Table not found');
        return;
    }
    
    // Create printable content
    const printContent = `
        <html>
        <head>
            <title>Top Talkers Report</title>
            <style>
                body { font-family: Arial, sans-serif; padding: 20px; }
                h1 { color: #1e293b; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                th { background: #1e293b; color: white; padding: 10px; text-align: left; }
                td { padding: 8px; border-bottom: 1px solid #ddd; }
                .footer { margin-top: 30px; color: #64748b; font-size: 12px; }
                .stats { margin-top: 20px; }
            </style>
        </head>
        <body>
            <h1>📊 Top Talkers Report</h1>
            <p>Generated on: ${new Date().toLocaleString()}</p>
            ${table.outerHTML}
            <div class="stats">
                <p><strong>Total Packets:</strong> ${document.getElementById('total-packets').innerText}</p>
                <p><strong>Uptime:</strong> ${document.getElementById('uptime').innerText}</p>
                <p><strong>CPU Usage:</strong> ${document.getElementById('cpu-usage').innerText}</p>
                <p><strong>Memory Usage:</strong> ${document.getElementById('memory-usage').innerText}</p>
            </div>
            <div class="footer">
                <p>Network Traffic Analysis Tool - SOC Dashboard</p>
            </div>
        </body>
        </html>
    `;
    
    // Open print window
    const win = window.open('', '_blank');
    win.document.write(printContent);
    win.document.close();
    
    // Print after load
    setTimeout(() => {
        win.print();
    }, 500);
}

// ============================================
// 📄 EXPORT JSON
// ============================================
function exportJSON() {
    console.log('Exporting JSON...');
    
    Promise.all([
        fetch('/api/top/talkers').then(res => res.json()),
        fetch('/api/stats').then(res => res.json())
    ])
    .then(([talkers, stats]) => {
        const data = {
            exported_at: new Date().toISOString(),
            total_packets: stats.total_packets || 0,
            protocol_counts: stats.protocol_counts || [],
            top_talkers: talkers || [],
            system_info: {
                os: document.getElementById('system-os')?.innerText || 'Unknown',
                python: document.getElementById('system-python')?.innerText || 'Unknown',
                uptime: document.getElementById('uptime')?.innerText || '0s',
                cpu: document.getElementById('cpu-usage')?.innerText || '0%',
                memory: document.getElementById('memory-usage')?.innerText || '0%'
            }
        };
        
        const json = JSON.stringify(data, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `dashboard_export_${new Date().toISOString().slice(0,10)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        console.log('JSON exported successfully');
    })
    .catch(err => {
        console.error('Export JSON error:', err);
        alert('Error exporting JSON: ' + err.message);
    });
}