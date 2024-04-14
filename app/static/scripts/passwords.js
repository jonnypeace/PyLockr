import { base64ToArrayBuffer, reEncryptDEKWithSharedSecret, importServerPublicKey,
         arrayBufferToBase64, keyPairGenerate, getSharedSecret, keyExchangeShare,
        deriveAESKeyFromSharedSecret} from './utils.js';

document.addEventListener('DOMContentLoaded', function () {
    var generateButton = document.getElementById('generatePasswordButton');
    if (generateButton) {
        generateButton.addEventListener('click', generateAndFillPassword);
    }

    var passwordToggle = document.getElementById('showPassword');
    if (passwordToggle) {
        passwordToggle.addEventListener('change', togglePasswordVisibility);
    }
});

function generatePassword(length) {
    var charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+<>?";
    var password = "";
    var values = new Uint8Array(length);
    window.crypto.getRandomValues(values);

    for (var i = 0; i < length; i++) {
        password += charset[values[i] % charset.length];
    }
    return password;
}
function generateAndFillPassword() {
    var length = document.getElementById('passwordLength').value;
    var password = generatePassword(length);
    document.getElementById('password').value = password;
}
function togglePasswordVisibility() {
    var passwordField = document.getElementById('password');
    var passwordToggle = document.getElementById('showPassword');
    if (passwordToggle.checked) {
        passwordField.type = 'text';
    } else {
        passwordField.type = 'password';
    }
}

document.addEventListener('DOMContentLoaded', () => {
    let isFormSubmitted = false; // Flag to prevent infinite submission loop
    var form = document.getElementById('addPassForm');
    form.addEventListener('submit', async function(e) {
        if (!isFormSubmitted) {
            e.preventDefault();
            const { publicKey, privateKey } = await keyPairGenerate();
            const salt = window.crypto.getRandomValues(new Uint8Array(16));
            const saltB64 = window.btoa(String.fromCharCode.apply(null, salt));
            const csrfToken = document.querySelector('input[name="csrf_token"]').value;
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const data = await getEdek(publicKey, saltB64, csrfToken, iv);
            const info = "ECDH AES-GCM"; // Ensure this info is the same on both client and server
            const passwordField = form.querySelector('input[name="password"]');
            if (data) {
                console.log("Complete data received:", data.serverPublicKey);
                const sharedSecret = await getSharedSecret(privateKey, data.serverPublicKey);
                const kek = await deriveAESKeyFromSharedSecret(sharedSecret.sharedSecret, salt, info) 
                const dekArrayBuffer = await decryptDEKWithSharedSecret(kek, data.edek, iv);
                const dek = await importAesKeyFromBuffer(dekArrayBuffer);
                const { encryptedData, ivPass } = await encryptStringWithAesGcm(dek, passwordField.value)
                console.log(`${encryptedData}`); // SUCCESS UP TO THIS POINT!! Needs converted to B64 and sent to server
                isFormSubmitted = true;
                // form.submit();
            }
        }}
    )}
);


function encryptData(data, edek, iv) {
    console.log(`Encrypting data using EDEK: ${edek} and IV: ${iv}`);
    // Your encryption logic here
}


async function getEdek(publicKey, saltB64, csrfToken, iv) {
    const ivB64 = arrayBufferToBase64(iv)
    const confirmResponse = await fetch('/get_user_edek_iv', {
        method: 'POST',  // Changed to GET since no body data is needed
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken  // CSRF token is still needed if your server requires it for all requests
        },
        body: JSON.stringify({publicKey: publicKey, salt: saltB64, iv: ivB64}),
    });
    if (confirmResponse.ok) {
        const data = await confirmResponse.json();
        const serverPublickKey = await importServerPublicKey(data.serverPubKeyB64);
        const edek = base64ToArrayBuffer(data.edek);
        return {edek: edek, serverPublicKey: serverPublickKey};
    };
    console.error('An error occurred');
    return false 
}

async function decryptDEKWithSharedSecret(sharedSecret, encryptedDEK, iv) {
    // Assume sharedSecret is already a CryptoKey suitable for decryption
    if (!(sharedSecret instanceof CryptoKey && sharedSecret.usages.includes('decrypt'))) {
        throw new Error("Provided shared secret is not a valid CryptoKey for decryption.");
    }

    // Use the shared secret directly to decrypt the DEK
    const decryptedDEK = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        sharedSecret,
        encryptedDEK);
    return decryptedDEK; // Return the decrypted DEK for further use
}

async function encryptStringWithAesGcm(aesKey, passwordString) {
    // Convert the password string to an ArrayBuffer (UTF-8)
    const encoder = new TextEncoder(); // Encoder to convert string to Uint8Array
    const passwordBytes = encoder.encode(passwordString); // Convert string to bytes

    // Generate a random Initialization Vector (IV) for AES-GCM
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 12 bytes IV for AES-GCM

    try {
        // Encrypt the password bytes with the AES key
        const encryptedData = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            aesKey,
            passwordBytes // ArrayBuffer of password
        );

        return { encryptedData, iv };
    } catch (error) {
        console.error("Failed to encrypt data:", error);
        throw error; // Rethrow to handle the error externally
    }
}

async function importAesKeyFromBuffer(arrayBuffer) {
    try {
        const key = await window.crypto.subtle.importKey(
            "raw",  // format of the key to import
            arrayBuffer,  // the ArrayBuffer containing the key data
            {
                name: "AES-GCM",
                length: 256
            },
            false,  // whether the key is extractable
            ["encrypt", "decrypt"]  // key usages
        );
        return key;
    } catch (error) {
        console.error("Error importing AES key from ArrayBuffer:", error);
        throw error;  // Rethrow to maintain error context
    }
}
