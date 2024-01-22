function copyToClipboard(element) {
    var passwordId = element.getAttribute('data-password-id');
    
    fetch('/decrypt_password/' + passwordId)
        .then(response => response.text())
        .then(text => {
            // Create a temporary textarea element to hold the password
            var textarea = document.createElement('textarea');
            textarea.value = text; // The decrypted password
            document.body.appendChild(textarea);

            // Select the text and copy it to the clipboard
            textarea.select();
            document.execCommand('copy');

            // Remove the temporary textarea
            document.body.removeChild(textarea);

            // Optionally, show a message to the user
            alert('Password copied to clipboard!');
        })
        .catch(error => console.error('Error:', error));
}
