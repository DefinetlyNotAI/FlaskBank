document.getElementById('rulesForm').addEventListener('submit', function (e) {
    e.preventDefault();

    const allowLeaderboard = document.getElementById('allowLeaderboard').checked;
    const allowPublicLogs = document.getElementById('allowPublicLogs').checked;
    const allowDebts = document.getElementById('allowDebts').checked;
    const allowSelfReview = document.getElementById('allowSelfReview').checked;
    const csrfToken = document.querySelector('input[name="csrf_token"]').value;

    // Show loading state
    Swal.fire({
        title: 'Saving rules...',
        text: 'Please wait',
        allowOutsideClick: false,
        didOpen: () => {
            Swal.showLoading();
        }
    });

    fetchData('/api/setup/rules', {
        method: 'POST',
        headers: {
            'X-CSRFToken': csrfToken,
        },
        body: JSON.stringify({
            allow_leaderboard: allowLeaderboard,
            allow_public_logs: allowPublicLogs,
            allow_debts: allowDebts,
            allow_self_review: allowSelfReview
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
                text: error.message || 'Failed to save rules',
                icon: 'error',
                confirmButtonText: 'OK'
            });
        });
});