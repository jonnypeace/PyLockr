import { base64ToArrayBuffer, reEncryptDEKWithSharedSecret, importServerPublicKey,
         arrayBufferToBase64, keyPairGenerate, getSharedSecret, deriveAESKeyFromSharedSecret,
         keyExchangeShare, finalExchange, getDek, getEdek, decryptData,
         encryptStringWithAesGcm, importAesKeyFromBuffer} from './utils.js';


function showToast(message, duration = 8000) {
    const container = document.getElementById('toast-container') || createToastContainer();
    const toast = document.createElement('div');
    toast.className = 'toast-message';
    toast.textContent = message;
    container.appendChild(toast);

    // Fade in the toast
    setTimeout(() => toast.style.opacity = 1, 100);

    // Automatically hide and remove the toast after 'duration'
    setTimeout(() => {
        toast.style.opacity = 0;
        toast.addEventListener('transitionend', () => toast.remove());
    }, duration);
}

function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
    return container;
}

document.addEventListener('DOMContentLoaded', () => {
    let isFormSubmitted = false; 
    const backupForm = document.getElementById('backupForm'); // Ensure your form has this ID
    backupForm.addEventListener('submit', function(e) {
        if (!isFormSubmitted) {
            e.preventDefault();
            showToast('Please test backup with the password you provided');
            isFormSubmitted = true;
            form.submit();
        }
    });
});

async function encryptFileWithAesGcm(aesKey, file) {
    const fileReader = new FileReader();

    // Create a Promise to handle reading the file
    const arrayBuffer = await new Promise((resolve, reject) => {
        fileReader.onload = () => resolve(fileReader.result);
        fileReader.onerror = () => reject(fileReader.error);
        fileReader.readAsArrayBuffer(file);
    });

    // Generate a random Initialization Vector (IV) for AES-GCM
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 12 bytes IV for AES-GCM

    try {
        // Encrypt the ArrayBuffer with the AES key
        const encryptedData = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            aesKey,
            arrayBuffer // ArrayBuffer of file data
        );

        return { encryptedData, iv };
    } catch (error) {
        console.error("Failed to encrypt file:", error);
        throw error; // Rethrow to handle the error externally
    }
}


async function encryptAndSendFile(aesKey, file) {
    const { encryptedData, iv } = await encryptFileWithAesGcm(aesKey, file);

    // Convert ArrayBuffer to Base64
    function bufferToBase64(buffer) {
        let binary = '';
        let bytes = new Uint8Array(buffer);
        let len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    // Prepare data to send
    const encryptedDataB64 = bufferToBase64(encryptedData);
    const ivB64 = bufferToBase64(iv);

    // Data to send as JSON
    const dataToSend = JSON.stringify({
        encryptedData: encryptedDataB64,
        iv: ivB64
    });

    // Fetch API to send data to the server
    fetch('YOUR_FLASK_SERVER_ENDPOINT', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: dataToSend
    })
    .then(response => response.json())
    .then(data => console.log('Response from server:', data))
    .catch(error => console.error('Error sending encrypted data:', error));
}