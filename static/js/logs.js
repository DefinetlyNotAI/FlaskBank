function loadLogs() {
    fetch('/api/get/logs')
        .then(response => response.json())
        .then(data => {
            const tableBody = document.getElementById('logsBody');
            if (data.length === 0) {
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

// Load logs on page load
window.addEventListener('load', function () {
    loadLogs();
});