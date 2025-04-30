document.addEventListener('DOMContentLoaded', function () {
    const refreshBtn = document.getElementById('refreshBtn');

    // Load health data on page load and when refresh button is clicked
    loadHealthData();

    refreshBtn.addEventListener('click', function () {
        loadHealthData();
    });

    // Auto-refresh every 30 seconds
    setInterval(loadHealthData, 30000);

    function loadHealthData() {
        fetch('/api/get/health')
            .then(response => response.json())
            .then(data => {
                updateSystemResources(data.system);
                updateDatabaseStatus(data.database);
                updateServerActivity(data.metrics);

                // Update last updated time
                document.getElementById('lastUpdated').textContent = new Date().toLocaleString();
            })
            .catch(error => {
                console.error('Error:', error);
                Swal.fire({
                    title: 'Error!',
                    text: 'Failed to load server health data',
                    icon: 'error',
                    confirmButtonText: 'OK'
                });
            });
    }

    function updateSystemResources(system) {
        // Update memory usage
        const memoryProgress = document.getElementById('memoryProgress');
        memoryProgress.style.width = `${system.memory_percent}%`;
        memoryProgress.setAttribute('aria-valuenow', system.memory_percent);
        memoryProgress.textContent = `${system.memory_percent}%`;

        // Set color based on usage
        if (system.memory_percent > 80) {
            memoryProgress.classList.remove('bg-info', 'bg-warning', 'bg-success');
            memoryProgress.classList.add('bg-danger');
        } else if (system.memory_percent > 50) {
            memoryProgress.classList.remove('bg-info', 'bg-danger', 'bg-success');
            memoryProgress.classList.add('bg-warning');
        } else {
            memoryProgress.classList.remove('bg-warning', 'bg-danger', 'bg-success');
            memoryProgress.classList.add('bg-info');
        }

        // Update disk usage
        const diskProgress = document.getElementById('diskProgress');
        diskProgress.style.width = `${system.disk_percent}%`;
        diskProgress.setAttribute('aria-valuenow', system.disk_percent);
        diskProgress.textContent = `${system.disk_percent}%`;

        // Set color based on usage
        if (system.disk_percent > 80) {
            diskProgress.classList.remove('bg-info', 'bg-warning', 'bg-success');
            diskProgress.classList.add('bg-danger');
        } else if (system.disk_percent > 50) {
            diskProgress.classList.remove('bg-info', 'bg-danger', 'bg-success');
            diskProgress.classList.add('bg-warning');
        } else {
            diskProgress.classList.remove('bg-danger', 'bg-success', 'bg-info');
            diskProgress.classList.add('bg-warning');
        }
    }

    function updateDatabaseStatus(database) {
        // Update database connection status
        const dbStatus = document.getElementById('dbStatus');
        dbStatus.textContent = database.connected ? 'Connected' : 'Disconnected';
        dbStatus.className = database.connected ? 'badge bg-success' : 'badge bg-danger';

        // Update database metrics
        document.getElementById('totalUsers').textContent = database.total_users;
        document.getElementById('totalRequests').textContent = database.total_requests;
        document.getElementById('totalLogs').textContent = database.total_logs;
    }

    function updateServerActivity(metrics) {
        const metricsBody = document.getElementById('metricsBody');
        metricsBody.innerHTML = '';

        metrics.forEach(metric => {
            const tr = document.createElement('tr');

            // Metric name
            const tdName = document.createElement('td');
            tdName.textContent = metric.name;
            tr.appendChild(tdName);

            // Metric value
            const tdValue = document.createElement('td');
            tdValue.textContent = metric.value;
            tr.appendChild(tdValue);

            // Metric status
            const tdStatus = document.createElement('td');
            const statusBadge = document.createElement('span');
            statusBadge.className = `badge bg-${metric.status === 'good' ? 'success' : metric.status === 'warning' ? 'warning' : 'danger'}`;
            statusBadge.textContent = metric.status.charAt(0).toUpperCase() + metric.status.slice(1);
            tdStatus.appendChild(statusBadge);
            tr.appendChild(tdStatus);

            metricsBody.appendChild(tr);
        });
    }
});