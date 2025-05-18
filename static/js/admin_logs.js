function loadAdminLogs() {
    fetch('/api/get/admin/logs')
        .then(response => response.json())
        .then(data => {
            const tableBody = document.getElementById('adminLogsBody');
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
            document.getElementById('adminLogsBody').innerHTML =
                '<tr><td colspan="3" class="text-center text-danger">Error loading logs</td></tr>';
        });
}

// Purge logs button
document.getElementById('purgeLogsBtn').addEventListener('click', function () {
    const purgeModal = new bootstrap.Modal(document.getElementById('purgeLogsModal'));
    purgeModal.show();
});

const csrfToken = document.querySelector('#csrfForm input[name="csrf_token"]').value;

// Update the purge logs button to ensure page refresh
document.getElementById('confirmPurgeBtn').addEventListener('click', function () {
    // Show loading state
    Swal.fire({
        title: 'Purging logs...',
        text: 'Please wait',
        allowOutsideClick: false,
        didOpen: () => {
            Swal.showLoading();
        }
    });

    fetch('/api/admin/purgeLogs', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken,
        },
        body: JSON.stringify({}),
    })
        .then(response => response.json())
        .then(data => {
            if (data.message) {
                Swal.fire({
                    title: 'Success!',
                    text: data.message,
                    icon: 'success',
                    confirmButtonText: 'OK'
                }).then(() => {
                    const purgeModal = bootstrap.Modal.getInstance(document.getElementById('purgeLogsModal'));
                    purgeModal.hide();
                    // Always refresh the page after a successful action
                    location.reload();
                });
            }
        })
        .catch((error) => {
            Swal.fire({
                title: 'Error!',
                text: error.message || 'Failed to purge logs',
                icon: 'error',
                confirmButtonText: 'OK'
            });
        });
});

// Load admin logs on page load
window.addEventListener('load', function () {
    loadAdminLogs();
});
