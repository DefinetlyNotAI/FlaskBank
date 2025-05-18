function loadWallets() {
    fetch('/api/get/walletList')
        .then(response => response.json())
        .then(data => {
            const tableBody = document.getElementById('walletsBody');
            if (data.length === 0) {
                tableBody.innerHTML = '<tr><td colspan="4" class="text-center">No wallets found</td></tr>';
                return;
            }

            let html = '';
            data.forEach(wallet => {
                html += `
                    <tr>
                        <td>${wallet.wallet_name}</td>
                        <td>${wallet.balance} ${wallet.currency}</td>
                        <td>
                            <span class="badge bg-${wallet.is_frozen ? 'danger' : 'success'}">
                                ${wallet.is_frozen ? 'Frozen' : 'Active'}
                            </span>
                        </td>
                        <td>
                            <div class="btn-group" role="group">
                                <a href="/admin/wallet/${wallet.wallet_name}" class="btn btn-sm btn-primary">Details</a>
                                <a href="/wallet/${wallet.wallet_name}" class="btn btn-sm btn-outline-secondary">View</a>
                            </div>
                        </td>
                    </tr>
                `;
            });
            tableBody.innerHTML = html;
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('walletsBody').innerHTML =
                '<tr><td colspan="4" class="text-center text-danger">Error loading wallets</td></tr>';
        });
}

// Create Wallet Form
document.getElementById('createWalletForm').addEventListener('submit', function (e) {
    e.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const initialCurrency = document.getElementById('initialCurrency').value;
    const csrfToken = document.querySelector('input[name="csrf_token"]').value;

    // Show loading state
    Swal.fire({
        title: 'Creating wallet...',
        text: 'Please wait',
        allowOutsideClick: false,
        didOpen: () => {
            Swal.showLoading();
        }
    });

    fetchData('/api/setup/wallet', {
        method: 'POST',
        headers: {
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({
            username: username,
            password: password,
            initial_currency: initialCurrency
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
                    // Always refresh the page after a successful action
                    location.reload();
                });
            }
        })
        .catch((error) => {
            Swal.fire({
                title: 'Error!',
                text: error.message || 'Failed to create wallet',
                icon: 'error',
                confirmButtonText: 'OK'
            });
        });
});

// Load wallets on page load
window.addEventListener('load', function () {
    loadWallets();
});
