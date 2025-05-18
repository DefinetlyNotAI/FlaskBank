document.addEventListener('DOMContentLoaded', function () {
    const sqlQueryForm = document.getElementById('sqlQueryForm');
    const sqlQuery = document.getElementById('sqlQuery');
    const resultsHeader = document.getElementById('resultsHeader');
    const resultsBody = document.getElementById('resultsBody');
    const rowCount = document.getElementById('rowCount');

    // Quick access buttons
    document.getElementById('showUsers').addEventListener('click', function () {
        document.getElementById('sqlQuery').value = '';
        sqlQuery.value = 'SELECT * FROM users ORDER BY wallet_name';
        executeQuery();
    });
    document.getElementById('changeBankName').addEventListener('click', function () {
        document.getElementById('sqlQuery').value = '';
        sqlQuery.value = 'UPDATE settings SET bank_name = \'New Bank Name\' WHERE id = 1;';
    });

    document.getElementById('changeCurrencyName').addEventListener('click', function () {
        document.getElementById('sqlQuery').value = '';
        sqlQuery.value = 'UPDATE settings SET currency_name = \'New Currency Name\' WHERE id = 1; ';
    });

    document.getElementById('showRequests').addEventListener('click', function () {
        document.getElementById('sqlQuery').value = '';
        sqlQuery.value = 'SELECT * FROM requests ORDER BY timestamp DESC LIMIT 100';
        executeQuery();
    });

    document.getElementById('showLogs').addEventListener('click', function () {
        document.getElementById('sqlQuery').value = '';
        sqlQuery.value = 'SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100';
        executeQuery();
    });

    document.getElementById('showLogsArchive').addEventListener('click', function () {
        document.getElementById('sqlQuery').value = '';
        sqlQuery.value = 'SELECT * FROM logs_archive ORDER BY timestamp DESC LIMIT 100';
        executeQuery();
    });

    document.getElementById('showSettings').addEventListener('click', function () {
        document.getElementById('sqlQuery').value = '';
        sqlQuery.value = 'SELECT * FROM settings';
        executeQuery();
    });

    // Execute query form
    sqlQueryForm.addEventListener('submit', function (e) {
        e.preventDefault();
        if (!['showUsers', 'showRequests', 'showLogs', 'showSettings', 'showLogsArchive'].some(id => document.activeElement.id === id)) {
            executeQuery();
        }
    });

    // Update the executeQuery function to add data attributes for admin protection
    function executeQuery() {
        const query = sqlQuery.value.trim();
        const csrfToken = document.querySelector('input[name="csrf_token"]').value;

        if (!query) {
            Swal.fire({
                title: 'Error!',
                text: 'Please enter a SQL query',
                icon: 'error',
                confirmButtonText: 'OK'
            });
            return;
        }

        // Show loading state
        Swal.fire({
            title: 'Executing query...',
            text: 'Please wait',
            allowOutsideClick: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });

        fetch('/api/admin/sql', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({
                query: query
            }),
        })
            .then(response => response.json())
            .then(data => {
                Swal.close();

                if (data.error) {
                    Swal.fire({
                        title: 'Error!',
                        text: data.error,
                        icon: 'error',
                        confirmButtonText: 'OK'
                    });
                    return;
                }

                // If it's not a SELECT query and was successful, refresh the page
                if (data.message && !query.toLowerCase().trim().startsWith('select')) {
                    Swal.fire({
                        title: 'Success!',
                        text: data.message,
                        icon: 'success',
                        confirmButtonText: 'OK'
                    }).then(() => {
                        location.reload();
                    });
                    return;
                }

                // Update row count
                rowCount.textContent = `${data.results.length} rows`;

                // Clear previous results
                resultsHeader.innerHTML = '';
                resultsBody.innerHTML = '';

                if (data.results.length === 0) {
                    resultsHeader.innerHTML = '<tr><th>No data</th></tr>';
                    resultsBody.innerHTML = '<tr><td>No results found</td></tr>';
                    return;
                }

                // Create header
                const headerRow = document.createElement('tr');
                Object.keys(data.results[0]).forEach(key => {
                    const th = document.createElement('th');
                    th.textContent = key;
                    headerRow.appendChild(th);
                });

                // Add delete button column if not a SELECT query
                if (!query.toLowerCase().trim().startsWith('select')) {
                    const th = document.createElement('th');
                    th.textContent = 'Actions';
                    headerRow.appendChild(th);
                }

                resultsHeader.appendChild(headerRow);

                // Create rows
                data.results.forEach(row => {
                    const tr = document.createElement('tr');

                    // Add data attributes for admin protection
                    if (row.wallet_name === 'admin') {
                        tr.setAttribute('data-wallet-name', 'admin');
                    }
                    if (row.id !== undefined) {
                        tr.setAttribute('data-id', row.id);
                    }

                    Object.values(row).forEach(value => {
                        const td = document.createElement('td');

                        // Format value based on type
                        if (value === null) {
                            td.textContent = 'NULL';
                            td.classList.add('text-muted');
                        } else if (typeof value === 'object' && value instanceof Date) {
                            td.textContent = value.toLocaleString();
                        } else if (typeof value === 'boolean') {
                            td.textContent = value ? 'true' : 'false';
                        } else {
                            td.textContent = String(value);
                        }

                        tr.appendChild(td);
                    });

                    // Add delete button if applicable
                    if (query.toLowerCase().trim().startsWith('select') &&
                        (row.id !== undefined || row.ticket_uuid !== undefined || row.wallet_name !== undefined)) {

                        const td = document.createElement('td');
                        const deleteBtn = document.createElement('button');
                        deleteBtn.className = 'btn btn-sm btn-danger';
                        deleteBtn.textContent = 'Delete';

                        // Determine which table and identifier to use
                        let deleteTable = '';
                        let identifierField = '';
                        let identifierValue = '';

                        if (query.toLowerCase().includes('from users')) {
                            deleteTable = 'users';
                            identifierField = 'wallet_name';
                            identifierValue = row.wallet_name;
                        } else if (query.toLowerCase().includes('from requests')) {
                            deleteTable = 'requests';
                            identifierField = 'ticket_uuid';
                            identifierValue = row.ticket_uuid;
                        } else if (query.toLowerCase().includes('from logs')) {
                            deleteTable = 'logs';
                            identifierField = 'id';
                            identifierValue = row.id;
                        }

                        if (deleteTable && identifierField && identifierValue) {
                            // Disable delete button for admin account
                            if (deleteTable === 'users' && identifierField === 'wallet_name' && identifierValue === 'admin') {
                                deleteBtn.disabled = true;
                                deleteBtn.title = 'Cannot delete admin account';
                                deleteBtn.classList.add('opacity-50');
                            } else {
                                deleteBtn.addEventListener('click', function () {
                                    deleteRecord(deleteTable, identifierField, identifierValue);
                                });
                            }
                            td.appendChild(deleteBtn);
                        }

                        tr.appendChild(td);
                    }

                    resultsBody.appendChild(tr);
                });
            })
            .catch(error => {
                Swal.close();
                Swal.fire({
                    title: 'Error!',
                    text: 'Failed to execute query: ' + error.message,
                    icon: 'error',
                    confirmButtonText: 'OK'
                });
            });
    }

    // Update the deleteRecord function to handle admin account protection
    function deleteRecord(table, field, value) {
        // Prevent deleting admin account
        if (table === 'users' && ((field === 'wallet_name' && value === 'admin') ||
            (field === 'id' && document.querySelector(`tr[data-wallet-name="admin"]`)?.getAttribute('data-id') === value))) {
            Swal.fire({
                title: 'Error!',
                text: 'Cannot delete the admin account',
                icon: 'error',
                confirmButtonText: 'OK'
            });
            return;
        }

        Swal.fire({
            title: 'Confirm Delete',
            text: `Are you sure you want to delete this record from ${table}?`,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'Yes, delete it!'
        }).then((result) => {
            if (result.isConfirmed) {
                // Show loading state
                Swal.fire({
                    title: 'Deleting...',
                    text: 'Please wait',
                    allowOutsideClick: false,
                    didOpen: () => {
                        Swal.showLoading();
                    }
                });

                fetch('/api/admin/delete-record', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        table: table,
                        field: field,
                        value: value
                    }),
                })
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            Swal.fire({
                                title: 'Error!',
                                text: data.error,
                                icon: 'error',
                                confirmButtonText: 'OK'
                            });
                        } else {
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
                    .catch(error => {
                        Swal.fire({
                            title: 'Error!',
                            text: 'Failed to delete record: ' + error.message,
                            icon: 'error',
                            confirmButtonText: 'OK'
                        });
                    });
            }
        });
    }
});
