// Updated function to accept a password ID directly
function copyToClipboard(passwordId) {
    fetch('/decrypt_password/' + passwordId)
        .then(response => response.text())
        .then(text => {
            // Using the Clipboard API
            if (navigator.clipboard) {
                navigator.clipboard.writeText(text).then(() => {
                    showToast(); // Show success message
                }).catch(err => {
                    console.error('Failed to copy with Clipboard API: ', err);
                    fallbackCopyTextToClipboard(text); // Fallback method
                });
            } else {
                // Fallback for browsers without Clipboard API support
                fallbackCopyTextToClipboard(text);
            }
        })
        .catch(error => console.error('Error:', error));
}

// Fallback method using execCommand for older browsers
function fallbackCopyTextToClipboard(text) {
    var textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    try {
        var successful = document.execCommand('copy');
        var msg = successful ? 'successful' : 'unsuccessful';
        console.log('Fallback: Copying text command was ' + msg);
        showToast(); // Assuming showToast() shows a generic success message
    } catch (err) {
        console.error('Fallback: Oops, unable to copy', err);
    }
    document.body.removeChild(textarea);
}

function showToast() {
    var toast = document.getElementById("toast");
    toast.style.display = "block";
    setTimeout(function() { toast.style.display = "none"; }, 3000); // Hide after 3 seconds
}
