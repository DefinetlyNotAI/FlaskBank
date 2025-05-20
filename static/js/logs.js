let cachedLogs = [];

function loadLogs() {
    fetch('/api/get/logs')
        .then(response => response.json())
        .then(data => {
            cachedLogs = data;
            const tableBody = document.getElementById('logsBody');
            if (!data.length) {
                tableBody.innerHTML = '<tr><td colspan="3" class="text-center">No logs found</td></tr>';
                return;
            }

            let html = '';
            data.forEach(log => {
                html += `
                    <tr>
                        <td>${new Date(log.timestamp).toLocaleString()}</td>
                        <td>${log.action}</td>
                        <td>${log.details}</td>
                    </tr>
                `;
            });
            tableBody.innerHTML = html;
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('logsBody').innerHTML =
                '<tr><td colspan="3" class="text-center text-danger">Error loading logs</td></tr>';
        });
}

function exportLogsAsCSV() {
    if (!cachedLogs.length) {
        Swal.fire('No Logs', 'There are no logs to export.', 'info');
        return;
    }

    const headers = ['Timestamp', 'Action', 'Details'];
    const rows = cachedLogs.map(log => [
        new Date(log.timestamp).toLocaleString(),
        log.action,
        log.details
    ]);

    const csv = [headers, ...rows]
        .map(row => row.map(field => `"${(field || '').replace(/"/g, '""')}"`).join(','))
        .join('\n');

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = `public_logs_${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '_')}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

window.addEventListener('load', function () {
    loadLogs();

    const exportBtn = document.getElementById('exportPublicCsvBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportLogsAsCSV);
    }
});
