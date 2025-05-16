document.addEventListener('DOMContentLoaded', function () {
    const setupForm = document.getElementById('setupForm');

    setupForm.addEventListener('submit', function (e) {
        // Prevent the default form submission
        e.preventDefault();

        const bankName = document.getElementById('bankName').value;
        const currencyName = document.getElementById('currencyName').value;
        const adminPassword = document.getElementById('adminPassword').value;

        // Validate form inputs
        if (!bankName || !currencyName || !adminPassword) {
            Swal.fire({
                title: 'Error!',
                text: 'Please fill in all fields',
                icon: 'error',
                confirmButtonText: 'OK'
            });
            return;
        }

        // Show loading state
        Swal.fire({
            title: 'Initializing...',
            text: 'Setting up your bank system, This may take some time!',
            allowOutsideClick: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });

        // Directly call the setup API
        fetch('/api/setup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                bank_name: bankName,
                currency_name: currencyName,
                admin_password: adminPassword
            })
        })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => {
                        throw new Error(data.error || 'Failed to initialize bank system');
                    });
                }
                return response.json();
            })
            .then(data => {
                if (data.message) {
                    Swal.fire({
                        title: 'Success!',
                        text: 'Bank system initialized successfully!',
                        icon: 'success',
                        confirmButtonText: 'Continue'
                    }).then(() => {
                        window.location.href = '/';
                    });
                }
            })
            .catch((error) => {
                Swal.fire({
                    title: 'Error!',
                    text: error.message || 'Failed to initialize bank system',
                    icon: 'error',
                    confirmButtonText: 'Try Again'
                });
            });
    });
});