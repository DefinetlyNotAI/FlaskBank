document.addEventListener('DOMContentLoaded', function () {
    // Approve Request Buttons
    document.querySelectorAll('.approve-btn').forEach(button => {
        button.addEventListener('click', function () {
            const requestUuid = this.getAttribute('data-request-uuid');
            const isWalletCreation = this.hasAttribute('data-wallet-creation');

            let title = 'Approve Request';
            let text = 'Are you sure you want to approve this request?';

            if (isWalletCreation) {
                title = 'Create Wallet';
                text = 'Are you sure you want to create this wallet?';
            }

            Swal.fire({
                title: title,
                text: text,
                icon: 'question',
                showCancelButton: true,
                confirmButtonColor: '#28a745',
                cancelButtonColor: '#6c757d',
                confirmButtonText: 'Yes, Approve'
            }).then((result) => {
                if (result.isConfirmed) {
                    // Show loading state
                    Swal.fire({
                        title: 'Processing...',
                        text: 'Approving request',
                        allowOutsideClick: false,
                        didOpen: () => {
                            Swal.showLoading();
                        }
                    });

                    fetch('/api/admin/approveRequest', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            request_ticket_uuid: requestUuid
                        }),
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
                                    location.reload();
                                });
                            } else {
                                Swal.fire({
                                    title: 'Error!',
                                    text: data.error || 'Failed to approve request',
                                    icon: 'error',
                                    confirmButtonText: 'OK'
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
                }
            });
        });
    });

    // Reject Request Buttons
    document.querySelectorAll('.reject-btn').forEach(button => {
        button.addEventListener('click', function () {
            const requestUuid = this.getAttribute('data-request-uuid');

            Swal.fire({
                title: 'Reject Request',
                text: 'Are you sure you want to reject this request?',
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#dc3545',
                cancelButtonColor: '#6c757d',
                confirmButtonText: 'Yes, Reject'
            }).then((result) => {
                if (result.isConfirmed) {
                    // Show loading state
                    Swal.fire({
                        title: 'Processing...',
                        text: 'Rejecting request',
                        allowOutsideClick: false,
                        didOpen: () => {
                            Swal.showLoading();
                        }
                    });

                    fetch('/api/admin/rejectRequest', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            request_ticket_uuid: requestUuid
                        }),
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
                                    location.reload();
                                });
                            } else {
                                Swal.fire({
                                    title: 'Error!',
                                    text: data.error || 'Failed to reject request',
                                    icon: 'error',
                                    confirmButtonText: 'OK'
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
                }
            });
        });
    });
});
