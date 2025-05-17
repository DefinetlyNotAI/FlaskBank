// Helper function for AJAX requests
async function fetchData(url, options = {}) {
    const defaultOptions = {
        headers: {
            "Content-Type": "application/json",
        },
    }

    const mergedOptions = {...defaultOptions, ...options}
    if (options.headers) {
        mergedOptions.headers = {...defaultOptions.headers, ...options.headers}
    }

    try {
        const response = await fetch(url, mergedOptions)
        const data = await response.json()

        if (!response.ok) {
            throw new Error(data.error || "An error occurred")
        }

        return data
    } catch (error) {
        console.error("Fetch error:", error)
        throw error
    }
}

// Confirm dangerous actions
function confirmAction(title, text, icon, confirmButtonText, callback) {
    Swal.fire({
        title: title,
        text: text,
        icon: icon,
        showCancelButton: true,
        confirmButtonColor: "#d33",
        cancelButtonColor: "#3085d6",
        confirmButtonText: confirmButtonText,
    }).then((result) => {
        if (result.isConfirmed) {
            callback()
        }
    })
}
