function loadLeaderboard() {
    fetch('/api/get/leaderboard')
        .then(response => response.json())
        .then(data => {
            const tableBody = document.getElementById('leaderboardBody');
            if (data.length === 0) {
                tableBody.innerHTML = '<tr><td colspan="4" class="text-center">No wallets found</td></tr>';
                return;
            }

            let html = '';
            data.forEach((wallet, index) => {
                html += `
                    <tr>
                        <td>${index + 1}</td>
                        <td>${wallet.wallet_name}</td>
                        <td>${wallet.balance} ${wallet.currency}</td>
                        <td>
                            <a href="/wallet/${wallet.wallet_name}" class="btn btn-sm btn-outline-primary">View</a>
                        </td>
                    </tr>
                `;
            });
            tableBody.innerHTML = html;
        })
        .catch(error => {
            console.error('Error:', error);
            Swal.fire({
                title: 'Error!',
                text: 'Failed to load leaderboard data',
                icon: 'error',
                confirmButtonText: 'OK'
            });
            document.getElementById('leaderboardBody').innerHTML =
                '<tr><td colspan="4" class="text-center text-danger">Error loading leaderboard</td></tr>';
        });
}

// Load leaderboard on page load
window.addEventListener('load', function () {
    loadLeaderboard();
});
