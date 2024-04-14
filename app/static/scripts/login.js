import { base64ToArrayBuffer, decryptDEK, keyPairGenerate, keyExchangeShare} from './utils.js';

async function hashPassword(password) {
    // Encode the password as UTF-8
    const msgBuffer = new TextEncoder().encode(password);

    // Hash the password
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);

    // Convert the ArrayBuffer to a hex string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return hashHex;
}

async function authenticateUser(username, password, csrfToken) {
    const authResponse = await fetch('/authenticate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken // Include CSRF token in the request headers
        },
        body: JSON.stringify({username: username, password: password}),
    });
    const { encryptedDEK, iv } = await authResponse.json();
    if (!authResponse.ok) {
        throw new Error('Authentication failed');
    }
    return { encryptedDEK: encryptedDEK, iv: iv };
}

///////////////////


document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('loginForm');
    // Assume csrf_token is available either as a hidden input field in the form or set elsewhere

    form.addEventListener('submit', async function(e) {
        e.preventDefault();

        const usernameField = form.querySelector('input[name="username"]');
        const passwordField = form.querySelector('input[name="password"]');
        const hashedPassword = await hashPassword(passwordField.value);
        const csrfToken = document.querySelector('input[name="csrf_token"]').value;

        try {
            const { encryptedDEK, iv } = await authenticateUser(usernameField.value, hashedPassword, csrfToken)
            // Convert from Base64 to ArrayBuffer before passing to decryptDEK
            const encryptedDEKArrayBuffer = base64ToArrayBuffer(encryptedDEK);
            const ivArrayBuffer = base64ToArrayBuffer(iv);
            const info = "ECDH AES-GCM"; // Ensure this info is the same on both client and server
            // Now, encryptedDEKArrayBuffer and ivArrayBuffer are in the correct format
            const dek = await decryptDEK(passwordField.value, encryptedDEKArrayBuffer, ivArrayBuffer);
            const { publicKey, privateKey } = await keyPairGenerate();
            const salt = window.crypto.getRandomValues(new Uint8Array(16));
            const saltB64 = window.btoa(String.fromCharCode.apply(null, salt));
            const finalResponse = await keyExchangeShare(publicKey, privateKey, salt, saltB64, dek, info, csrfToken);
            if (finalResponse) {
                // Assuming your async operations are successful...
                passwordField.value = hashedPassword
                form.submit(); // Proceed with traditional form submission
            }
            else {
                console.error('An error occurred');
                // Handle the error, display feedback to the user
            }
        } catch (error) {
            console.error('Authentication error:', error);
            // Implement user feedback based on the error
        }
    });
});

