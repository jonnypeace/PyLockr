function copyToClipboard(passwordId) {
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

    fetch('/decrypt_password/' + passwordId, {
        method: 'POST', // Assuming decrypt operation is a POST request for security reasons
        headers: {
            'Content-Type': 'application/json',
            'csrf_token': csrfToken, // Here you set the CSRF token in the request headers
        },
        body: JSON.stringify({ passwordId: passwordId }) // If your backend expects JSON, ensure to send the passwordId in the body
    })
    .then(response => response.json()) // Parse the JSON response
    .then(data => {
        // Extract the password from the parsed JSON object
        const password = data.password;
        // Use the Clipboard API to copy the extracted password
        if (navigator.clipboard) {
            navigator.clipboard.writeText(password).then(() => {
                showToast(); // Show success message
            }).catch(err => {
                console.error('Failed to copy with Clipboard API: ', err);
            });
        } else {
            fallbackCopyTextToClipboard(password); // Use the fallback method with the extracted password
        }
    })
    .catch(error => console.error('Error:', error));
}

// Updated function to accept a password ID directly
// function copyToClipboard(passwordId) {
//     fetch('/decrypt_password/' + passwordId)
//         .then(response => response.text())
//         .then(text => {
//             // Using the Clipboard API
//             if (navigator.clipboard) {
//                 navigator.clipboard.writeText(text).then(() => {
//                     showToast(); // Show success message
//                 }).catch(err => {
//                     console.error('Failed to copy with Clipboard API: ', err);
//                     fallbackCopyTextToClipboard(text); // Fallback method
//                 });
//             } else {
//                 // Fallback for browsers without Clipboard API support
//                 fallbackCopyTextToClipboard(text);
//             }
//         })
//         .catch(error => console.error('Error:', error));
// }

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
        showToast();
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
