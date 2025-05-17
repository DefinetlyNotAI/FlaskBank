const dataEl = document.getElementById('currency-data');

const totalUsed = parseFloat(dataEl.dataset.totalUsed);
const available = parseFloat(dataEl.dataset.available);
const currencyName = dataEl.dataset.currencyName;

const ctx = document.getElementById('currencyChart').getContext('2d');
const currencyChart = new Chart(ctx, {
    type: 'pie',
    data: {
        labels: ['In Circulation', 'Available'],
        datasets: [{
            data: [totalUsed, available],
            backgroundColor: [
                'rgba(54, 162, 235, 0.8)',
                'rgba(75, 192, 192, 0.8)'
            ],
            borderColor: [
                'rgba(54, 162, 235, 1)',
                'rgba(75, 192, 192, 1)'
            ],
            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        plugins: {
            legend: {
                position: 'bottom'
            }
        }
    }
});

// Mint Form
document.getElementById('mintForm').addEventListener('submit', function (e) {
    e.preventDefault();

    const amount = document.getElementById('mintAmount').value;

    // Show confirmation dialog
    Swal.fire({
        title: 'Confirm Mint',
        text: `Are you sure you want to mint ${amount} ${currencyName}?`,
        icon: 'question',
        showCancelButton: true,
        confirmButtonText: 'Yes, Mint Currency',
        cancelButtonText: 'Cancel'
    }).then((result) => {
        if (result.isConfirmed) {
            // Show loading state
            Swal.fire({
                title: 'Minting currency...',
                text: 'Please wait',
                allowOutsideClick: false,
                didOpen: () => {
                    Swal.showLoading();
                }
            });

            fetch('/api/admin/mintCurrency', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    amount: amount
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
                            // Always refresh the page after a successful action
                            location.reload();
                        });
                    } else {
                        Swal.fire({
                            title: 'Error!',
                            text: data.error || 'Failed to mint currency',
                            icon: 'error',
                            confirmButtonText: 'OK'
                        });
                    }
                })
                .catch((error) => {
                    Swal.fire({
                        title: 'Error!',
                        text: error.message || 'Failed to mint currency',
                        icon: 'error',
                        confirmButtonText: 'OK'
                    });
                });
        }
    });
});

// Burn Form
document.getElementById('burnForm').addEventListener('submit', function (e) {
    e.preventDefault();

    const amount = document.getElementById('burnAmount').value;

    // Show confirmation dialog
    Swal.fire({
        title: 'Confirm Burn',
        text: `Are you sure you want to burn ${amount} ${currencyName}?`,
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#d33',
        confirmButtonText: 'Yes, Burn Currency',
        cancelButtonText: 'Cancel'
    }).then((result) => {
        if (result.isConfirmed) {
            // Show loading state
            Swal.fire({
                title: 'Burning currency...',
                text: 'Please wait',
                allowOutsideClick: false,
                didOpen: () => {
                    Swal.showLoading();
                }
            });

            fetch('/api/admin/burnCurrency', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    amount: amount
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
                            // Always refresh the page after a successful action
                            location.reload();
                        });
                    } else {
                        Swal.fire({
                            title: 'Error!',
                            text: data.error || 'Failed to burn currency',
                            icon: 'error',
                            confirmButtonText: 'OK'
                        });
                    }
                })
                .catch((error) => {
                    Swal.fire({
                        title: 'Error!',
                        text: error.message || 'Failed to burn currency',
                        icon: 'error',
                        confirmButtonText: 'OK'
                    });
                });
        }
    });
});