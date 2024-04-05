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

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('loginForm');
    // Assume csrf_token is available either as a hidden input field in the form or set elsewhere
    const csrfToken = document.querySelector('input[name="csrf_token"]').value; 

    form.addEventListener('submit', async function(e) {
        e.preventDefault();

        const usernameField = form.querySelector('input[name="username"]');
        const passwordField = form.querySelector('input[name="password"]');
        const hashedPassword = await hashPassword(passwordField.value);

        try {
            const authResponse = await fetch('/authenticate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken // Include CSRF token in the request headers
                },
                body: JSON.stringify({username: usernameField.value, password: hashedPassword}),
            });
            const { encryptedDEK, iv } = await authResponse.json();
            if (!authResponse.ok) {
                throw new Error(authData.message || 'Authentication failed');
            }
            // Assuming `encryptedDEK` and `iv` are fetched from the server as Base64 strings

            // Convert from Base64 to ArrayBuffer before passing to decryptDEK
            const encryptedDEKArrayBuffer = base64ToArrayBuffer(encryptedDEK);
            const ivArrayBuffer = base64ToArrayBuffer(iv);
        
            // Now, encryptedDEKArrayBuffer and ivArrayBuffer are in the correct format
            const dek = await decryptDEK(passwordField.value, encryptedDEKArrayBuffer, ivArrayBuffer);

            // Decrypt EDEK here and store DEK
            const dekBase64 = arrayBufferToBase64(dek);

            // Send the decrypted DEK to the server via the /send_dek endpoint, along with CSRF token
            const confirmResponse = await fetch('/send_dek', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken // Include CSRF token here as well
                },
                body: JSON.stringify({dek: dekBase64}),
            });

            if (!confirmResponse.ok) {
                throw new Error('Failed to confirm authentication');
            }
            // Modify the form's action if needed, or keep it as is if it's already set to the /login endpoint
            try {
                // Assuming your async operations are successful...
                passwordField.value = hashedPassword
                form.submit(); // Proceed with traditional form submission
            } catch (error) {
                console.error('An error occurred:', error);
                // Handle the error, display feedback to the user
            }
        } catch (error) {
            console.error('Authentication error:', error);
            // Implement user feedback based on the error
        }
    });
});

/////////////////////////////////////////////////////

// Utility function to convert Base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {
    var binary_string = window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

function arrayBufferToBase64(buffer) {
    var binary = '';
    var bytes = new Uint8Array(buffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}


async function decryptDEK(password, encryptedDEK, iv) {
    // Derive KEK from the password, using the same parameters as at signup
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { "name": "PBKDF2" },
        false,
        ["deriveKey"]);

    const kek = await window.crypto.subtle.deriveKey(
        {
            "name": "PBKDF2",
            salt: enc.encode("boyah-baby"), // Ensure this matches signup
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { "name": "AES-GCM", "length": 256},
        true,
        ["decrypt", "encrypt"]);

    // Decrypt eDEK with KEK
    const decryptedDEK = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        kek,
        encryptedDEK);

    return decryptedDEK; // Return the decrypted DEK for further use
}