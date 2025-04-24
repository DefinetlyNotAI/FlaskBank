// Approve Request Buttons
document.querySelectorAll('.approve-btn').forEach(button => {
    button.addEventListener('click', function () {
        const requestUuid = this.getAttribute('data-request-uuid');

        Swal.fire({
            title: 'Approving request...',
            text: 'Please wait',
            allowOutsideClick: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });

        fetchData('/api/admin/approveRequest', {
            method: 'POST',
            body: JSON.stringify({
                request_ticket_uuid: requestUuid
            })
        })
            .then(data => {
                if (data.message) {
                    Swal.fire({
                        title: 'Success!',
                        text: data.message,
                        icon: 'success',
                        confirmButtonText: 'OK'
                    }).then(() => {
                        location.reload();
                    });
                }
            })
            .catch((error) => {
                Swal.fire({
                    title: 'Error!',
                    text: error.message || 'Failed to approve request',
                    icon: 'error',
                    confirmButtonText: 'OK'
                });
            });
    });
});

// Reject Request Buttons
document.querySelectorAll('.reject-btn').forEach(button => {
    button.addEventListener('click', function () {
        const requestUuid = this.getAttribute('data-request-uuid');

        Swal.fire({
            title: 'Rejecting request...',
            text: 'Please wait',
            allowOutsideClick: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });

        fetchData('/api/admin/rejectRequest', {
            method: 'POST',
            body: JSON.stringify({
                request_ticket_uuid: requestUuid
            })
        })
            .then(data => {
                if (data.message) {
                    Swal.fire({
                        title: 'Success!',
                        text: data.message,
                        icon: 'success',
                        confirmButtonText: 'OK'
                    }).then(() => {
                        location.reload();
                    });
                }
            })
            .catch((error) => {
                Swal.fire({
                    title: 'Error!',
                    text: error.message || 'Failed to reject request',
                    icon: 'error',
                    confirmButtonText: 'OK'
                });
            });
    });
});
