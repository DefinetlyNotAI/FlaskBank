function loadRequests() {
    const requestsList = document.getElementById('requestsList');

    fetch('/api/get/wallet/logs?limit=100')
        .then(response => response.json())
        .then(data => {
            // Filter logs to find request-related entries
            const requestLogs = data.filter(log =>
                log.action.includes('Request') &&
                log.details.includes('Pending')
            );

            if (requestLogs.length === 0) {
                requestsList.innerHTML = '<div class="text-center text-muted">No pending requests</div>';
                return;
            }

            let html = '';
            requestLogs.forEach(log => {
                // Extract request UUID from log details (simplified)
                const uuidMatch = log.details.match(/request ticket uuid: ([a-f0-9-]+)/i);
                const requestUuid = uuidMatch ? uuidMatch[1] : '';

                html += `
                    <div class="list-group-item list-group-item-action">
                        <div class="d-flex w-100 justify-content-between">
                            <h6 class="mb-1">${log.action}</h6>
                            <small>${new Date(log.timestamp).toLocaleString()}</small>
                        </div>
                        <p class="mb-1">${log.details}</p>
                        <div class="d-flex justify-content-end mt-2">
                            <button class="btn btn-sm btn-success me-2 approve-btn" data-request-uuid="${requestUuid}">Approve</button>
                            <button class="btn btn-sm btn-danger reject-btn" data-request-uuid="${requestUuid}">Reject</button>
                        </div>
                    </div>
                `;
            });
            requestsList.innerHTML = html;

            // Add event listeners to buttons
            document.querySelectorAll('.approve-btn').forEach(button => {
                button.addEventListener('click', function () {
                    approveRequest(this.getAttribute('data-request-uuid'));
                });
            });

            document.querySelectorAll('.reject-btn').forEach(button => {
                button.addEventListener('click', function () {
                    rejectRequest(this.getAttribute('data-request-uuid'));
                });
            });
        })
        .catch(error => {
            console.error('Error:', error);
            requestsList.innerHTML = '<div class="text-center text-danger">Error loading requests</div>';
        });
}

const csrfToken = document.querySelector('#csrfForm input[name="csrf_token"]').value;

function approveRequest(requestUuid) {
    fetch('/api/admin/approveRequest', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({
            request_ticket_uuid: requestUuid
        }),
    })
        .then(response => response.json())
        .then(data => {
            if (data.message) {
                alert(data.message);
                loadRequests();
            } else {
                alert('Error: ' + data.error);
            }
        })
        .catch((error) => {
            alert('Error: ' + error);
        });
}

function rejectRequest(requestUuid) {
    fetch('/api/admin/rejectRequest', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({
            request_ticket_uuid: requestUuid
        }),
    })
        .then(response => response.json())
        .then(data => {
            if (data.message) {
                alert(data.message);
                loadRequests();
            } else {
                alert('Error: ' + data.error);
            }
        })
        .catch((error) => {
            alert('Error: ' + error);
        });
}

// Load requests on page load
window.addEventListener('load', function () {
    loadRequests();
});