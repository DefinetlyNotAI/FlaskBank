// Update the refund button to use log ID instead of UUID
// Update the loadUserLogs function to check for existing refund requests
function loadUserLogs() {
    // First, fetch all refund requests to know which logs already have refund requests
    fetch('/api/get/user/requests?limit=500')
        .then(response => response.json())
        .then(requestsData => {
            // Extract log IDs that already have refund requests
            const refundedLogIds = new Set();
            requestsData.forEach(req => {
                if (req.request_type === 'Refund') {
                    // Extract log ID from reason (e.g., "Refund for log ID 123: reason text")
                    const match = req.reason.match(/log ID (\d+):/);
                    if (match && match[1]) {
                        refundedLogIds.add(parseInt(match[1]));
                    }
                }
            });

            // Now fetch the logs
            return fetch('/api/get/wallet/logs')
                .then(response => response.json())
                .then(data => {
                    const tableBody = document.getElementById('userLogsBody');
                    if (data.length === 0) {
                        tableBody.innerHTML = '<tr><td colspan="4" class="text-center">No logs found</td></tr>';
                        return;
                    }

                    let html = '';
                    data.forEach(log => {
                        // Check if this is a transfer log that might be refundable
                        const isTransfer = log.action === 'Transfer' && log.details.includes('{{ session.wallet_name }} transferred');
                        const alreadyRefunded = refundedLogIds.has(log.id);

                        html += `
                            <tr>
                                <td>${new Date(log.timestamp).toLocaleString()}</td>
                                <td>${log.action}</td>
                                <td>${log.details}</td>
                                <td>
                                    ${isTransfer && !alreadyRefunded ?
                            `<button class="btn btn-sm btn-outline-warning refund-btn"
                                            data-log-id="${log.id}" data-log-details="${log.details}">
                                            Request Refund
                                        </button>` :
                            alreadyRefunded ? '<span class="badge bg-info">Refund Requested</span>' : ''}
                                </td>
                            </tr>
                        `;
                    });
                    tableBody.innerHTML = html;

                    // Add event listeners to refund buttons
                    document.querySelectorAll('.refund-btn').forEach(button => {
                        button.addEventListener('click', function () {
                            const logId = this.getAttribute('data-log-id');
                            const logDetails = this.getAttribute('data-log-details');
                            document.getElementById('transferUuid').value = logId;
                            const refundModal = new bootstrap.Modal(document.getElementById('refundModal'));
                            refundModal.show();
                        });
                    });
                });
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('userLogsBody').innerHTML =
                '<tr><td colspan="4" class="text-center text-danger">Error loading logs</td></tr>';
        });
}

// Remove the extractTransferUuid function as it's no longer needed

// Update the submit refund function to use log ID
document.getElementById('submitRefund').addEventListener('click', function () {
    const logId = document.getElementById('transferUuid').value;
    const reason = document.getElementById('refundReason').value;

    if (!reason) {
        Swal.fire({
            title: 'Error!',
            text: 'Please provide a reason for the refund',
            icon: 'error',
            confirmButtonText: 'OK'
        });
        return;
    }

    // Show loading state
    Swal.fire({
        title: 'Submitting refund request...',
        text: 'Please wait',
        allowOutsideClick: false,
        didOpen: () => {
            Swal.showLoading();
        }
    });

    fetch('/api/request/refund', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            log_id: logId,
            reason: reason
        })
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
                    const refundModal = bootstrap.Modal.getInstance(document.getElementById('refundModal'));
                    refundModal.hide();
                    // Always refresh the page after a successful action
                    location.reload();
                });
            } else {
                Swal.fire({
                    title: 'Error!',
                    text: data.error || 'Failed to submit refund request',
                    icon: 'error',
                    confirmButtonText: 'OK'
                });
            }
        })
        .catch((error) => {
            Swal.fire({
                title: 'Error!',
                text: error.message || 'Failed to submit refund request',
                icon: 'error',
                confirmButtonText: 'OK'
            });
        });
});

// Load user logs on page load
window.addEventListener('load', function () {
    loadUserLogs();
});