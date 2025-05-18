// Form validation
(function () {
    'use strict';

    // Fetch all forms we want to apply validation to
    const forms = document.querySelectorAll('.needs-validation');

    // Loop over them and prevent submission
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });
})();

// Update the Balance Chart section to include three segments instead of two
// Replace the existing Balance Chart code with this:

// Balance Chart
const ctx = document.getElementById('balanceChart').getContext('2d');
const is_admin = window.location.pathname.includes('/wallet/admin');

if (ctx) {
    const walletDataEl = document.getElementById('walletData');
    const userCurrent = parseInt(walletDataEl.dataset.userCurrent);
    const totalUsed = parseInt(walletDataEl.dataset.totalUsed);
    const maxCurrency = parseInt(walletDataEl.dataset.maxCurrency);

    const balanceChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: is_admin
                ? ['In Circulation', 'Not in Circulation']
                : ['Your Balance', 'In Circulation (Others)', 'Available in Bank'],
            datasets: [{
                data: is_admin
                    ? [totalUsed, maxCurrency - totalUsed]
                    : [userCurrent, totalUsed - userCurrent, maxCurrency - totalUsed],
                backgroundColor: is_admin
                    ? ['rgba(255, 159, 64, 0.8)', 'rgba(75, 192, 192, 0.8)']
                    : ['rgba(54, 162, 235, 0.8)', 'rgba(255, 159, 64, 0.8)', 'rgba(75, 192, 192, 0.8)'],
                borderColor: is_admin
                    ? ['rgba(255, 159, 64, 1)', 'rgba(75, 192, 192, 1)']
                    : ['rgba(54, 162, 235, 1)', 'rgba(255, 159, 64, 1)', 'rgba(75, 192, 192, 1)'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        boxWidth: 12
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} ${percentage}%`;
                        }
                    }
                }
            }
        }
    });
}

// Load Recent Activity
async function loadRecentActivity() {
    try {
        const response = await fetch('/api/get/wallet/logs?limit=5');
        const data = await response.json();

        const activityDiv = document.getElementById('recentActivity');
        if (data.length === 0) {
            activityDiv.innerHTML = '<p class="text-center text-muted">No recent activity</p>';
            return;
        }

        let html = '<ul class="list-group list-group-flush">';
        data.forEach(log => {
            html += `
                <li class="list-group-item">
                    <div class="d-flex w-100 justify-content-between">
                        <h6 class="mb-1">${log.action}</h6>
                        <small>${new Date(log.timestamp).toLocaleString()}</small>
                    </div>
                    <p class="mb-1">${log.details}</p>
                </li>
            `;
        });
        html += '</ul>';
        activityDiv.innerHTML = html;
    } catch (error) {
        console.error('Error:', error);
        document.getElementById('recentActivity').innerHTML =
            '<p class="text-center text-danger">Error loading activity</p>';
    }
}

// Transfer Form
// Update the success callback for the transfer form to ensure page refresh
const transferForm = document.getElementById('transferForm');
if (transferForm) {
    transferForm.addEventListener('submit', async function (e) {
        e.preventDefault();

        const form = this;
        if (!form.checkValidity()) {
            form.classList.add('was-validated');
            return;
        }

        const csrfToken = document.querySelector('input[name="csrf_token"]').value;
        const toWallet = document.getElementById('toWallet').value;
        const amount = document.getElementById('amount').value;
        const category = document.getElementById('category').value;
        const reason = document.getElementById('reason').value;

        // Show loading state
        Swal.fire({
            title: 'Processing...',
            text: 'Processing your transfer',
            allowOutsideClick: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });

        try {
            const data = await fetchData('/api/transfer/toWallet', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken  // Pass CSRF token here (note the header name)
                },
                body: JSON.stringify({
                    to_wallet: toWallet,
                    amount: amount,
                    category: category,
                    reason: reason
                })
            });

            Swal.fire({
                title: 'Success!',
                text: data.message,
                icon: 'success',
                confirmButtonText: 'OK'
            }).then(() => {
                // Always refresh the page after a successful action
                location.reload();
            });
        } catch (error) {
            Swal.fire({
                title: 'Error!',
                text: error.message,
                icon: 'error',
                confirmButtonText: 'OK'
            });
        }
    });
}

// Reset Password Form
// Update the reset password form to ensure page refresh
const resetPasswordForm = document.getElementById('resetPasswordForm');
if (resetPasswordForm) {
    resetPasswordForm.addEventListener('submit', async function (e) {
        e.preventDefault();

        const form = this;
        if (!form.checkValidity()) {
            form.classList.add('was-validated');
            return;
        }

        const newPassword = document.getElementById('newPassword').value;
        const reason = document.getElementById('resetReason').value;
        const csrfToken = document.querySelector('input[name="csrf_token"]').value;

        // Show loading state
        Swal.fire({
            title: 'Processing...',
            text: 'Processing your password reset request',
            allowOutsideClick: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });

        try {
            const data = await fetchData('/api/request/resetPassword', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken  // Pass CSRF token here (note the header name)
                },
                body: JSON.stringify({
                    new_password: newPassword,
                    reason: reason
                })
            });

            Swal.fire({
                title: 'Success!',
                text: data.message,
                icon: 'success',
                confirmButtonText: 'OK'
            }).then(() => {
                // Always refresh or redirect after a successful action
                if (data.message.includes('successfully')) {
                    location.href = '/login';
                } else {
                    location.reload();
                }
            });
        } catch (error) {
            Swal.fire({
                title: 'Error!',
                text: error.message,
                icon: 'error',
                confirmButtonText: 'OK'
            });
        }
    });
}

// Admin Bank Transfer Form
if (document.getElementById('bankTransferForm')) {
    document.getElementById('bankTransferForm').addEventListener('submit', async function (e) {
        e.preventDefault();

        const form = this;
        if (!form.checkValidity()) {
            form.classList.add('was-validated');
            return;
        }

        const amount = document.getElementById('bankAmount').value;
        const category = document.getElementById('bankCategory').value;
        const reason = document.getElementById('bankReason').value;

        confirmAction(
            'Confirm Bank Transfer',
            `Are you sure you want to transfer ${amount} ${amount > 0 ? 'to' : 'from'} this wallet?`,
            'warning',
            'Yes, Process Transfer',
            async () => {
                // Show loading state
                Swal.fire({
                    title: 'Processing...',
                    text: 'Processing bank transfer',
                    allowOutsideClick: false,
                    didOpen: () => {
                        Swal.showLoading();
                    }
                });

                try {
                    const data = await fetchData('/api/transfer/bank', {
                        method: 'POST',
                        body: JSON.stringify({
                            wallet_name: document.getElementById('walletData').dataset.walletName,
                            amount: amount,
                            category: category,
                            reason: reason
                        })
                    });

                    Swal.fire({
                        title: 'Success!',
                        text: data.message,
                        icon: 'success',
                        confirmButtonText: 'OK'
                    }).then(() => {
                        location.reload();
                    });
                } catch (error) {
                    Swal.fire({
                        title: 'Error!',
                        text: error.message,
                        icon: 'error',
                        confirmButtonText: 'OK'
                    });
                }
            }
        );
    });
}

// Admin Freeze/Unfreeze Button
// Find the freezeWalletBtn click event handler and update the fetch call
const freezeWalletBtn = document.getElementById('freezeWalletBtn');
if (freezeWalletBtn) {
    freezeWalletBtn.addEventListener('click', function () {
        Swal.fire({
            title: document.getElementById('walletData').dataset.isFrozen === 'True' ? 'Unfreeze Wallet' : 'Freeze Wallet',
            text: 'Please provide a reason:',
            input: 'textarea',
            inputAttributes: {
                minlength: 3,
                maxlength: 500,
                required: 'required'
            },
            showCancelButton: true,
            confirmButtonColor: document.getElementById('walletData').dataset.isFrozen === 'True' ? '#28a745' : '#ffc107',
            confirmButtonText: document.getElementById('walletData').dataset.isFrozen === 'True' ? 'Unfreeze' : 'Freeze',
            showLoaderOnConfirm: true,
            preConfirm: (reason) => {
                if (!reason || reason.length < 3) {
                    Swal.showValidationMessage('Reason must be at least 3 characters');
                    return false;
                }
                return reason;
            }
        }).then((result) => {
            if (result.isConfirmed) {
                const reason = result.value;
                const endpoint = document.getElementById('walletData').dataset.isFrozen === 'True' ? '/api/admin/unfreezeWallet' : '/api/admin/freezeWallet';
                const csrfToken = document.querySelector('input[name="csrf_token"]').value;

                fetch(endpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken  // Pass CSRF token here (note the header name)
                    },
                    body: JSON.stringify({
                        wallet_name: document.getElementById('walletData').dataset.walletName,
                        reason: reason
                    })
                })
                    .then(response => response.json())
                    .then(data => {
                        Swal.fire({
                            title: 'Success!',
                            text: data.message,
                            icon: 'success',
                            confirmButtonText: 'OK'
                        }).then(() => {
                            location.reload();
                        });
                    })
                    .catch(error => {
                        Swal.fire({
                            title: 'Error!',
                            text: error.message,
                            icon: 'error',
                            confirmButtonText: 'OK'
                        });
                    });
            }
        });
    });
}

// Admin Reset Button
// Update the resetWalletBtn click event handler
const resetWalletBtn = document.getElementById('resetWalletBtn');
if (resetWalletBtn) {
    resetWalletBtn.addEventListener('click', function () {
        confirmAction(
            'Reset Wallet',
            'This will set the wallet balance to 0 and delete all related logs. This action cannot be undone.',
            'warning',
            'Yes, Reset Wallet',
            () => {
                Swal.fire({
                    title: 'Reset Wallet',
                    text: 'Please provide a reason:',
                    input: 'textarea',
                    inputAttributes: {
                        minlength: 3,
                        maxlength: 500,
                        required: 'required'
                    },
                    showCancelButton: true,
                    confirmButtonColor: '#ffc107',
                    confirmButtonText: 'Reset Wallet',
                    showLoaderOnConfirm: true,
                    preConfirm: (reason) => {
                        if (!reason || reason.length < 3) {
                            Swal.showValidationMessage('Reason must be at least 3 characters');
                            return false;
                        }
                        return reason;
                    }
                }).then((result) => {
                    if (result.isConfirmed) {
                        const reason = result.value;
                        const csrfToken = document.querySelector('input[name="csrf_token"]').value;
                        fetch('/api/admin/resetWallet', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'X-CSRFToken': csrfToken  // Pass CSRF token here (note the header name)
                            },
                            body: JSON.stringify({
                                wallet_name: document.getElementById('walletData').dataset.walletName,
                                reason: reason
                            })
                        })
                            .then(response => response.json())
                            .then(data => {
                                Swal.fire({
                                    title: 'Success!',
                                    text: data.message,
                                    icon: 'success',
                                    confirmButtonText: 'OK'
                                }).then(() => {
                                    location.reload();
                                });
                            })
                            .catch(error => {
                                Swal.fire({
                                    title: 'Error!',
                                    text: error.message,
                                    icon: 'error',
                                    confirmButtonText: 'OK'
                                });
                            });
                    }
                });
            }
        );
    });
}

// Admin Burn Button
// Update the burnWalletBtn click event handler
const burnWalletBtn = document.getElementById('burnWalletBtn');
if (burnWalletBtn) {
    burnWalletBtn.addEventListener('click', function () {
        confirmAction(
            'Burn Wallet',
            'This will permanently delete the wallet and all associated data. This action cannot be undone.',
            'warning',
            'Yes, Burn Wallet',
            () => {
                Swal.fire({
                    title: 'Burn Wallet',
                    text: 'Please provide a reason:',
                    input: 'textarea',
                    inputAttributes: {
                        minlength: 3,
                        maxlength: 500,
                        required: 'required'
                    },
                    showCancelButton: true,
                    confirmButtonColor: '#dc3545',
                    confirmButtonText: 'Burn Wallet',
                    showLoaderOnConfirm: true,
                    preConfirm: (reason) => {
                        if (!reason || reason.length < 3) {
                            Swal.showValidationMessage('Reason must be at least 3 characters');
                            return false;
                        }
                        return reason;
                    }
                }).then((result) => {
                    if (result.isConfirmed) {
                        const reason = result.value;
                        const csrfToken = document.querySelector('input[name="csrf_token"]').value;
                        fetch('/api/admin/burnWallet', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'X-CSRFToken': csrfToken  // Pass CSRF token here (note the header name)
                            },
                            body: JSON.stringify({
                                wallet_name: document.getElementById('walletData').dataset.walletName,
                                reason: reason
                            })
                        })
                            .then(response => response.json())
                            .then(data => {
                                Swal.fire({
                                    title: 'Success!',
                                    text: data.message,
                                    icon: 'success',
                                    confirmButtonText: 'OK'
                                }).then(() => {
                                    window.location.href = '/admin/wallets';
                                });
                            })
                            .catch(error => {
                                Swal.fire({
                                    title: 'Error!',
                                    text: error.message,
                                    icon: 'error',
                                    confirmButtonText: 'OK'
                                });
                            });
                    }
                });
            }
        );
    });
}

// Load recent activity on page load
window.addEventListener('load', function () {
    loadRecentActivity();
});