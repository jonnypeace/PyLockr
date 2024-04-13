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
            // Convert from Base64 to ArrayBuffer before passing to decryptDEK
            const encryptedDEKArrayBuffer = base64ToArrayBuffer(encryptedDEK);
            const ivArrayBuffer = base64ToArrayBuffer(iv);
            const info = "ECDH AES-GCM"; // Ensure this info is the same on both client and server
            // Now, encryptedDEKArrayBuffer and ivArrayBuffer are in the correct format
            const dek = await decryptDEK(passwordField.value, encryptedDEKArrayBuffer, ivArrayBuffer);
            const { publicKey, privateKey } = await keyPairGenerate();
            const salt = window.crypto.getRandomValues(new Uint8Array(16));
            const saltB64 = window.btoa(String.fromCharCode.apply(null, salt));

            // send public key and salt to server for shared secret discovery
            const confirmResponse = await fetch('/keyexchange', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken // Include CSRF token here as well
                },
                body: JSON.stringify({publicKey: publicKey, salt: saltB64}),
            });

            if (confirmResponse.ok) {
                // If the HTTP status code is 200-299
                const responseData = await confirmResponse.json();
                const serverPublicKeyB64 = await responseData.serverPublicKey;
                const serverPublicKey = await importServerPublicKey(serverPublicKeyB64);
                const sharedSecret = await getSharedSecret(privateKey, serverPublicKey);
                const aesKey = await deriveAESKeyFromSharedSecret(sharedSecret.sharedSecret, salt, info);
                const { encryptedDEK, iv} = await reEncryptDEKWithSharedSecret(aesKey, dek);
                const edekBase64 = arrayBufferToBase64(encryptedDEK);
                const ivB64 = arrayBufferToBase64(iv);

                const finalResponse = await fetch('/secretprocessing', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken
                    },
                    body: JSON.stringify({edekBase64: edekBase64, ivB64: ivB64}),
                });
                if (!finalResponse.ok) {
                    console.error("Failed to process secrets:", await finalResponse.text());
                }
    
            } else {
                // Handle errors or unsuccessful responses
                console.error("Failed to exchange keys:", await confirmResponse.text());
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

async function keyPairGenerate() {
    const keyPair = await window.crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true, // whether the key is extractable (for the public key)
        ["deriveBits"] // 'deriveKey' usage is not required for ECDH in Web Crypto API
    );

    // Export the public key
    const publicKey = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);

    // Keep the private key in its secure, non-exported format
    // Convert the exported public key to a format (e.g., Base64) for transmission
    const publicKeyBase64 = arrayBufferToBase64(publicKey); // Assuming arrayBufferToBase64 is defined elsewhere

    return { publicKey: publicKeyBase64, privateKey: keyPair.privateKey };
};

// Example of importing the server's public key in the client
async function importServerPublicKey(serverPublicKeyBase64) {
    const serverPublicKeyBytes = window.atob(serverPublicKeyBase64);
    const serverPublicKeyArrayBuffer = new Uint8Array(serverPublicKeyBytes.length);
    for (let i = 0; i < serverPublicKeyBytes.length; i++) {
        serverPublicKeyArrayBuffer[i] = serverPublicKeyBytes.charCodeAt(i);
    }

    const serverPublicKey = await window.crypto.subtle.importKey(
        "spki",
        serverPublicKeyArrayBuffer.buffer,
        {
            name: "ECDH",
            namedCurve: "P-256"
        },
        true,
        []
    );
    return serverPublicKey;
}

async function getSharedSecret(clientPrivateKey, serverPublicKey) {
    // Derive shared secret
    const sharedSecret = await window.crypto.subtle.deriveBits(
        {
            name: "ECDH",
            public: serverPublicKey,
        },
        clientPrivateKey,
        256
        );
    return { sharedSecret }
}


async function deriveAESKeyFromSharedSecret(sharedSecret, salt, info) {    
    const sharedSecretKey = await window.crypto.subtle.importKey(
        "raw",
        sharedSecret, // The raw shared secret as an ArrayBuffer
        { name: "HKDF" },
        false, // Whether the key is extractable
        ["deriveKey"] // Specify the use for key derivation
    );
    console.log('sharedSecretKey imported as cryptokey for hkdf')

    // Derive the AES key using HKDF
    const aesKey = await window.crypto.subtle.deriveKey(
        {
            name: "HKDF",
            salt: salt, // The salt as an ArrayBuffer
            info: new TextEncoder().encode(info), // Info, context-specific application info
            hash: "SHA-256"
        },
        sharedSecretKey,
        { 
            name: "AES-GCM", 
            length: 256 // AES key length in bits
        },
        true, // Whether the derived key is extractable
        ["encrypt", "decrypt"] // The derived key can be used for these operations
    );

    return aesKey;
}


async function reEncryptDEKWithSharedSecret(aesKey, dek) {
    // Ensure the Initialization Vector (IV) for AES-GCM
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // IV for AES-GCM

    try {
        // Encrypt the DEK with the AES key directly
        const encryptedDEK = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            aesKey,
            dek // Ensure DEK is an ArrayBuffer
        );

        return { encryptedDEK, iv };
    } catch (error) {
        console.error("Failed to re-encrypt DEK:", error);
        throw error; // Proper error handling
    }
}
