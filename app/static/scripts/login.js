import { base64ToArrayBuffer, decryptDEK, keyPairGenerate, keyExchangeShare, encryptLoginPassword} from './utils.js';



async function authenticateUser(username, password, csrfToken) {
    const authResponse = await fetch('/authenticate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({username: username, password: password}),
    });
    const { encryptedDEK, iv, saltAuth } = await authResponse.json();
    if (!authResponse.ok) {
        alert('Authentication Failed')
        throw new Error('Authentication failed');
    }
    return { encryptedDEK: encryptedDEK, iv: iv, saltAuth: saltAuth };
}

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('loginForm');

    form.addEventListener('submit', async function(e) {
        e.preventDefault();

        const usernameField = form.querySelector('input[name="username"]');
        const passwordField = form.querySelector('input[name="password"]');
        const csrfToken = document.querySelector('input[name="csrf_token"]').value;
        
        try {
            const encryptedPass = await encryptLoginPassword(passwordField.value)
            const { encryptedDEK, iv, saltAuth } = await authenticateUser(usernameField.value, encryptedPass.encryptedPass, csrfToken)
            // Convert from Base64 to ArrayBuffer before passing to decryptDEK
            const encryptedDEKArrayBuffer = base64ToArrayBuffer(encryptedDEK);
            const ivArrayBuffer = base64ToArrayBuffer(iv);
            const saltAuthBuffer = base64ToArrayBuffer(saltAuth);
            const info = "ECDH AES-GCM"; // Ensure this info is the same on both client and server
            // Now, encryptedDEKArrayBuffer and ivArrayBuffer are in the correct format
            const dek = await decryptDEK(passwordField.value, encryptedDEKArrayBuffer, ivArrayBuffer, saltAuthBuffer);
            const { publicKey, privateKey } = await keyPairGenerate();
            const salt = window.crypto.getRandomValues(new Uint8Array(16));
            const saltB64 = window.btoa(String.fromCharCode.apply(null, salt));
            const finalResponse = await keyExchangeShare(publicKey, privateKey, salt, saltB64, dek, info, csrfToken);
            if (finalResponse) {
                // Assuming async operations are successful...
                passwordField.value = encryptedPass.encryptedPass;
                form.submit(); // Proceed with traditional form submission
            }
            else {
                console.error('An error occurred');
            }
        } catch (error) {
            console.error('Authentication error');
        }
    });
});

