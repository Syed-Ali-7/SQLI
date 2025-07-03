document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const errorMessage = document.getElementById('error-message');
    const profileContainer = document.querySelector('.profile-container');
    const passwordField = document.getElementById('password');
    const passwordToggle = document.getElementById('password-toggle');

    // Password toggle functionality
    if (passwordToggle) {
        passwordToggle.addEventListener('click', () => {
            const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordField.setAttribute('type', type);
            // Toggle the eye icon
            passwordToggle.querySelector('i').classList.toggle('fa-eye');
            passwordToggle.querySelector('i').classList.toggle('fa-eye-slash');
        });
    }

    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            const response = await fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            if (response.status === 403) {
                window.location.href = '/access-denied';
                return;
            }

            const data = await response.json();

            if (response.ok) {
                if (data.redirect_url) {
                    window.location.href = data.redirect_url;
                } else {
                    window.location.href = '/profile';
                }
            } else {
                errorMessage.textContent = data.error;
            }
        });
    }

    if (profileContainer) {
        const logoutBtn = document.getElementById('logout-btn');

        logoutBtn.addEventListener('click', async () => {
            await fetch('/logout', { method: 'POST' });
            window.location.href = '/';
        });
    }
});
