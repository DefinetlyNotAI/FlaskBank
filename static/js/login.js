document.getElementById('submitWalletRequest').addEventListener('click', function () {
    const walletName = document.getElementById('requestWalletName').value.trim();
    const password = document.getElementById('requestPassword').value.trim();
    const reason = document.getElementById('requestReason').value.trim();

    const forbiddenChars = /[|'"`;]/;

    // Basic validation
    if (!walletName || !password || !reason) {
        Swal.fire({
            title: 'Error!',
            text: 'Please fill in all fields',
            icon: 'error',
            confirmButtonText: 'OK'
        });
        return;
    }

    if (!/^[a-zA-Z0-9_]{3,100}$/.test(walletName)) {
        Swal.fire({
            title: 'Error!',
            text: 'Wallet name can only contain letters, numbers, and underscores',
            icon: 'error',
            confirmButtonText: 'OK'
        });
        return;
    }

    if (password.length < 8) {
        Swal.fire({
            title: 'Error!',
            text: 'Password must be at least 8 characters long',
            icon: 'error',
            confirmButtonText: 'OK'
        });
        return;
    }

    if (forbiddenChars.test(reason)) {
        Swal.fire({
            title: 'Error!',
            text: "Reason contains forbidden characters: | ' \" ; `",
            icon: 'error',
            confirmButtonText: 'OK'
        });
        return;
    }

    // Show loading state
    Swal.fire({
        title: 'Submitting request...',
        text: 'Please wait',
        allowOutsideClick: false,
        didOpen: () => {
            Swal.showLoading();
        }
    });

    // Submit the request
    fetch('/api/request/wallet', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            wallet_name: walletName,
            password: password,
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
                    // Close the modal
                    const modal = bootstrap.Modal.getInstance(document.getElementById('requestWalletModal'));
                    modal.hide();

                    // Clear the form
                    document.getElementById('requestWalletForm').reset();
                });
            } else {
                Swal.fire({
                    title: 'Error!',
                    text: data.error || 'Failed to submit wallet request',
                    icon: 'error',
                    confirmButtonText: 'OK'
                });
            }
        })
        .catch((error) => {
            Swal.fire({
                title: 'Error!',
                text: error.message || 'Failed to submit wallet request',
                icon: 'error',
                confirmButtonText: 'OK'
            });
        });
});