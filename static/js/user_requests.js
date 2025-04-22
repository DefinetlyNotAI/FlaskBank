function loadUserRequests() {
    fetch('/api/get/user/requests')
        .then(response => response.json())
        .then(data => {
            const tableBody = document.getElementById('userRequestsBody');
            if (data.length === 0) {
                tableBody.innerHTML = '<tr><td colspan="5" class="text-center">No requests found</td></tr>';
                return;
            }

            let html = '';
            data.forEach(request => {
                // Set status badge color
                let statusClass = 'bg-secondary';
                if (request.status === 'Approved') statusClass = 'bg-success';
                else if (request.status === 'Rejected') statusClass = 'bg-danger';
                else if (request.status === 'Pending') statusClass = 'bg-warning';

                html += `
                    <tr>
                        <td>${request.request_type}</td>
                        <td>${request.category || 'N/A'}</td>
                        <td>${request.reason}</td>
                        <td><span class="badge ${statusClass}">${request.status}</span></td>
                        <td>${new Date(request.timestamp).toLocaleString()}</td>
                    </tr>
                `;
            });
            tableBody.innerHTML = html;
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('userRequestsBody').innerHTML =
                '<tr><td colspan="5" class="text-center text-danger">Error loading requests</td></tr>';
        });
}

// Load user requests on page load
window.addEventListener('load', function () {
    loadUserRequests();
});