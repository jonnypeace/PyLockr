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
    // console.log(`${sharedSecretKey}`)
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

///////////////////////////////////////

async function getDek() {
    const { publicKey, privateKey } = await keyPairGenerate();
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const saltB64 = window.btoa(String.fromCharCode.apply(null, salt));
    const csrfToken = document.querySelector('input[name="csrf_token"]').value;
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const data = await getEdek(publicKey, saltB64, csrfToken, iv);
    const info = "ECDH AES-GCM"; // Ensure this info is the same on both client and server
    if (data) {
        // console.log("Complete data received:", data.serverPublicKey);
        const sharedSecret = await getSharedSecret(privateKey, data.serverPublicKey);
        const kek = await deriveAESKeyFromSharedSecret(sharedSecret.sharedSecret, salt, info) 
        const dekArrayBuffer = await decryptData(kek, data.edek, iv);
        const dek = await importAesKeyFromBuffer(dekArrayBuffer);
        return {kek: kek, dek: dek}
    }
    return null
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

async function decryptData(key, encryptedData, iv) {
    // Assume sharedSecret is already a CryptoKey suitable for decryption
    if (!(key instanceof CryptoKey && key.usages.includes('decrypt'))) {
        throw new Error("Provided kek is not a valid CryptoKey for decryption.");
    }
    try {
        // Use the shared secret directly to decrypt the DEK
        const decryptedData = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            encryptedData);
        console.log("Decryption successful");
        return decryptedData; // Return the decrypted DEK for further use
    } catch (error) {
        console.error('Error occurred', error);
        throw error;
    }
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



async function reEncryptDEKWithSharedSecret(aesKey, data) {
    // Ensure the Initialization Vector (IV) for AES-GCM
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // IV for AES-GCM

    try {
        // Encrypt the DEK with the AES key directly
        const encryptedDEK = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            aesKey,
            data // Ensure DEK/data/password string is an ArrayBuffer
        );

        return { encryptedDEK, iv };
    } catch (error) {
        console.error("Failed to re-encrypt DEK:", error);
        throw error; // Proper error handling
    }
}

async function keyExchangeShare(publicKey, privateKey, salt, saltB64, dek, info, csrfToken) {
    // send public key and salt to server for shared secret discovery
    const confirmResponse = await fetch('/keyexchange', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
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
        const finalResponse = await finalExchange(edekBase64, ivB64, csrfToken);
        return finalResponse;
    } else {
        // Handle errors or unsuccessful responses
        console.error("Failed to exchange keys:", await confirmResponse.text());
    }
}

async function finalExchange(edekBase64, ivB64, csrfToken){
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
    return finalResponse.ok;
}


// Properly export your functions
export { base64ToArrayBuffer, arrayBufferToBase64, decryptDEK,
         keyPairGenerate, importServerPublicKey, getSharedSecret, deriveAESKeyFromSharedSecret, reEncryptDEKWithSharedSecret,
         keyExchangeShare, finalExchange, getDek, getEdek, decryptData, encryptStringWithAesGcm, importAesKeyFromBuffer};