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
         keyExchangeShare, finalExchange};