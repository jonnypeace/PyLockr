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
    // Import the shared secret as a CryptoKey for HKDF
    const sharedSecretKey = await window.crypto.subtle.importKey(
        "raw",
        sharedSecret, // The raw shared secret as an ArrayBuffer
        { name: "HKDF" },
        false, // Whether the key is extractable
        ["deriveKey"] // Specify the use for key derivation
    );

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

// Example usage
const salt = window.crypto.getRandomValues(new Uint8Array(16)); // Should be the same salt used on the server-side
const info = "ECDH AES-GCM"; // Ensure this info is the same on both client and server
// Assume sharedSecret is obtained from the ECDH deriveBits operation
// const sharedSecret = await getSharedSecret(...);
// You'd then convert sharedSecret.sharedSecret (ArrayBuffer) to the correct format if necessary

// const aesKey = await deriveAESKeyFromSharedSecret(sharedSecret.sharedSecret, salt, info);


async function reEncryptDEKWithSharedSecret(aesKey, dek) {
    // Derive a symmetric encryption key from the shared secret
    // This might involve using the shared secret directly (if format/size is suitable) or processing it (e.g., hashing) to fit requirements
    const derivedKey = await window.crypto.subtle.importKey(
        "raw",
        aesKey, // Assuming sharedSecret is already in the correct format
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );

    // Encrypt the DEK with the derived symmetric key
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // IV for AES-GCM
    const encryptedDEK = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        derivedKey,
        dek // Assuming dek is an ArrayBuffer
    );

    return { encryptedDEK, iv };
}

// JavaScript: Example of preparing encryptedDEK and iv for transmission
const payload = {
    encryptedDEK: arrayBufferToBase64(encryptedDEK), // Assuming encryptedDEK is an ArrayBuffer and arrayBufferToBase64 is a conversion function
    iv: arrayBufferToBase64(iv) // Convert IV to a suitable format for transmission
};

// Then, send `payload` to the server

// from cryptography.hazmat.primitives.serialization import load_der_public_key
// from cryptography.hazmat.backends import default_backend
// from cryptography.hazmat.primitives.asymmetric import ec
// from base64 import b64decode

// # Assume client_public_key_b64 is the Base64-encoded public key received from the client
// client_public_key_bytes = b64decode(client_public_key_b64)

// # Load the public key
// client_public_key = load_der_public_key(client_public_key_bytes, backend=default_backend())

// # Generate server's private key for ECDH
// server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

// # Derive the shared secret
// shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)

// from cryptography.hazmat.primitives.ciphers.aead import AESGCM
// import base64

// def decrypt_edek(encrypted_edek_b64, iv_b64, kek):
//     # Decode the IV and encrypted EDEK from Base64
//     iv = base64.b64decode(iv_b64)
//     encrypted_edek = base64.b64decode(encrypted_edek_b64)
    
//     # Create an AESGCM instance with the KEK
//     aesgcm = AESGCM(kek)
    
//     # Decrypt the EDEK
//     dek = aesgcm.decrypt(iv, encrypted_edek, None)
    
//     return dek

// from cryptography.hazmat.primitives import hashes
// from cryptography.hazmat.primitives.kdf.hkdf import HKDF

// def derive_aes_key_from_shared_secret(shared_secret, salt):
//     # Derive a 256-bit AES key from the shared secret
//     hkdf = HKDF(
//         algorithm=hashes.SHA256(),
//         length=32,  # 256 bits for AES-256
//         salt=salt,
//         info=b'context-specific information',
//         backend=default_backend()
//     )
//     aes_key = hkdf.derive(shared_secret)
//     return aes_key

// # Example usage:
// # shared_secret = ...  # Obtained from ECDH exchange
// # salt = os.urandom(16)  # Should be a fixed value or stored alongside the encrypted data
// # kek = derive_aes_key_from_shared_secret(shared_secret, salt)
