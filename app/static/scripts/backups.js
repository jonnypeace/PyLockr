function showToast(message, duration = 8000) {
    const container = document.getElementById('toast-container') || createToastContainer();
    const toast = document.createElement('div');
    toast.className = 'toast-message';
    toast.textContent = message;
    container.appendChild(toast);

    // Fade in the toast
    setTimeout(() => toast.style.opacity = 1, 100);

    // Automatically hide and remove the toast after 'duration'
    setTimeout(() => {
        toast.style.opacity = 0;
        toast.addEventListener('transitionend', () => toast.remove());
    }, duration);
}

function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
    return container;
}

// Example usage: showToast('Backup download initiated. Please check your downloads folder.');

document.addEventListener('DOMContentLoaded', function() {
    const backupForm = document.getElementById('backupForm'); // Ensure your form has this ID
    backupForm.addEventListener('submit', function(e) {
        showToast('Please test backup with the password you provided');
        // No need to prevent the default form submission here
    });
});
