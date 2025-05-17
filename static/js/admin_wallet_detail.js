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

// Bank Transfer Form
document.getElementById('bankTransferForm').addEventListener('submit', function (e) {
    e.preventDefault();

    const amount = document.getElementById('bankAmount').value;
    const category = document.getElementById('bankCategory').value;
    const reason = document.getElementById('bankReason').value;

    Swal.fire({
        title: 'Processing transfer...',
        text: 'Please wait',
        allowOutsideClick: false,
        didOpen: () => {
            Swal.showLoading();
        }
    });

    fetchData('/api/transfer/bank', {
        method: 'POST',
        body: JSON.stringify({
            wallet_name: '{{ user.wallet_name }}',
            amount: amount,
            category: category,
            reason: reason
        })
    })
        .then(data => {
            if (data.message) {
                Swal.fire({
                    title: 'Success!',
                    text: 'Transfer successful!',
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
                text: error.message || 'Transfer failed',
                icon: 'error',
                confirmButtonText: 'OK'
            });
        });
});

// Admin Freeze/Unfreeze Button
document.getElementById('freezeButton').addEventListener('click', function () {
    const reason = document.getElementById('freezeReason').value;
    if (!reason) {
        Swal.fire({
            title: 'Error!',
            text: 'Please provide a reason',
            icon: 'error',
            confirmButtonText: 'OK'
        });
        return;
    }

    const endpoint = '{{ user.is_frozen }}' === 'True' ? '/api/admin/unfreezeWallet' : '/api/admin/freezeWallet';
    const action = '{{ user.is_frozen }}' === 'True' ? 'unfreezing' : 'freezing';

    // Show loading state
    Swal.fire({
        title: `${action.charAt(0).toUpperCase() + action.slice(1)} wallet...`,
        text: 'Please wait',
        allowOutsideClick: false,
        didOpen: () => {
            Swal.showLoading();
        }
    });

    fetch(endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            wallet_name: '{{ user.wallet_name }}',
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
                    location.reload();
                });
            }
        })
        .catch((error) => {
            Swal.fire({
                title: 'Error!',
                text: error.message || `Failed to ${action} wallet`,
                icon: 'error',
                confirmButtonText: 'OK'
            });
        });
});

// Admin Reset Button
document.getElementById('resetButton').addEventListener('click', function () {
    const reason = document.getElementById('resetWalletReason').value;
    if (!reason) {
        Swal.fire({
            title: 'Error!',
            text: 'Please provide a reason',
            icon: 'error',
            confirmButtonText: 'OK'
        });
        return;
    }

    Swal.fire({
        title: 'Resetting wallet...',
        text: 'Please wait',
        allowOutsideClick: false,
        didOpen: () => {
            Swal.showLoading();
        }
    });

    fetch('/api/admin/resetWallet', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            wallet_name: '{{ user.wallet_name }}',
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
                    location.reload();
                });
            }
        })
        .catch((error) => {
            Swal.fire({
                title: 'Error!',
                text: error.message || 'Failed to reset wallet',
                icon: 'error',
                confirmButtonText: 'OK'
            });
        });
});

// Admin Burn Button
document.getElementById('burnButton').addEventListener('click', function () {
    const reason = document.getElementById('burnReason').value;
    if (!reason) {
        Swal.fire({
            title: 'Error!',
            text: 'Please provide a reason',
            icon: 'error',
            confirmButtonText: 'OK'
        });
        return;
    }

    Swal.fire({
        title: 'Burning wallet...',
        text: 'Please wait',
        allowOutsideClick: false,
        didOpen: () => {
            Swal.showLoading();
        }
    });

    fetch('/api/admin/burnWallet', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            wallet_name: '{{ user.wallet_name }}',
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
                    window.location.href = '/admin/wallets';
                });
            }
        })
        .catch((error) => {
            Swal.fire({
                title: 'Error!',
                text: error.message || 'Failed to burn wallet',
                icon: 'error',
                confirmButtonText: 'OK'
            });
        });
});

