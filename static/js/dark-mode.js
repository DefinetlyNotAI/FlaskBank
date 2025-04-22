// Dark mode toggle functionality
document.addEventListener("DOMContentLoaded", () => {
    const darkModeToggle = document.getElementById("darkModeToggle")
    const htmlElement = document.documentElement

    // Check for saved theme preference or use preferred color scheme
    const savedTheme = localStorage.getItem("theme")
    const prefersDarkMode = window.matchMedia("(prefers-color-scheme: dark)").matches

    // Set initial theme
    if (savedTheme === "dark" || (!savedTheme && prefersDarkMode)) {
        htmlElement.setAttribute("data-bs-theme", "dark")
        if (darkModeToggle) {
            darkModeToggle.checked = true
        }
    } else {
        htmlElement.setAttribute("data-bs-theme", "light")
        if (darkModeToggle) {
            darkModeToggle.checked = false
        }
    }

    // Toggle theme when switch is clicked
    if (darkModeToggle) {
        darkModeToggle.addEventListener("change", function () {
            if (this.checked) {
                htmlElement.setAttribute("data-bs-theme", "dark")
                localStorage.setItem("theme", "dark")
            } else {
                htmlElement.setAttribute("data-bs-theme", "light")
                localStorage.setItem("theme", "light")
            }
        })
    }
})
