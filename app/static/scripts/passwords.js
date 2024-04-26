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

var passwordVisibilityToggled = false; // global var to keep track of encrypted or decrypted password.

function checkForm(){
    var form = document.getElementById('addPassForm');
    var formType = 'addPass';
    // If 'addPassForm' doesn't exist, check for 'editPassForm'
    if (!form) {
        form = document.getElementById('editPassForm');
        formType = 'editPass';
    }
    return {form: form, formType: formType}
}

async function togglePasswordVisibility() {
    var passwordField = document.getElementById('password');
    var passwordToggle = document.getElementById('showPassword');
    if (passwordToggle.checked) {
        const {form, formType} = checkForm();
        if (formType === 'addPass') {
            passwordField.type = 'text';
        } else {
            if (passwordVisibilityToggled === false) {
                try {
                    const dek = await getDek();
                    const iv = form.querySelector('input[name="ivPass"]');
                    const ivArr = base64ToArrayBuffer(iv.value);
                    const passArr = base64ToArrayBuffer(passwordField.value);
                    const passwordDecrypt = await decryptData(dek.dek, passArr, ivArr);
                    const password = new TextDecoder().decode(passwordDecrypt);
                    // const password = base64DecodeUtf8(passwordB64);
                    console.log(password)
                    passwordField.value = password;
                    passwordVisibilityToggled = true;
                    passwordField.type = 'text';
                } catch (error) {
                    console.error('Decryption failed');
                    alert('Failed to decrypt the password. Please refresh the page or try again.');
                    passwordField.type = 'password'; // Reset to password type on failure
                }
            } else {
                passwordField.type = 'password';
            }
        }
    } else {
        passwordField.type = 'password';
    }
}

function base64DecodeUtf8(base64) {
    // Decode Base64 to a binary string
    const binaryString = atob(base64);

    // Convert binary string to a character-number array
    const charCodeArray = Array.from(binaryString, c => c.charCodeAt(0));

    // Convert char code array to a byte array
    const byteArray = new Uint8Array(charCodeArray);

    // Decode byte array to a UTF-8 string
    const text = new TextDecoder('utf-8').decode(byteArray);

    return text;
}



document.addEventListener('DOMContentLoaded', () => {
    let isFormSubmitted = false; // Flag to prevent infinite submission loop
    const {form, formType} = checkForm();
    form.addEventListener('submit', async function(e) {
        if (!isFormSubmitted) {
            e.preventDefault();
            if ((passwordVisibilityToggled === true && formType === 'editPass') || formType === 'addPass') {
                const passwordField = form.querySelector('input[name="password"]');
                alert(passwordField.value);
                const dek = await getDek();
                if (dek) {
                    const { encryptedData: arrPassword, iv: ivArrPass } = await encryptStringWithAesGcm(dek.dek, passwordField.value);
                    const b64Password = arrayBufferToBase64(arrPassword);
                    const b64IV = arrayBufferToBase64(ivArrPass);
                    passwordField.value = b64Password;
                    form.querySelector('input[name="ivPass"]').value = b64IV;
                } else {
                    console.error('Failed to retrieve DEK');
                    return; // Handle the error appropriately
                }
            isFormSubmitted = true;
            form.submit();
            }
        }}
    )}
);

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
