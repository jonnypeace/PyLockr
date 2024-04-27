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
    backupForm.addEventListener('submit', async function(e) {
        if (!isFormSubmitted) {
            e.preventDefault();
            const passwordField = document.getElementById('backupPassword');
            const encKey = await getDek().catch(error => {
                console.error('Error fetching encryption key');
                showToast('Error fetching encryption key');
                return null;
            });
            if (passwordField && encKey) {
                const { encryptedData: arrPassword, iv: ivArrPass } = await encryptStringWithAesGcm(encKey.dek, passwordField.value).catch(error => {
                    console.error('Error encrypting password');
                    showToast('Error encrypting password');
                    return null;
                });
                const passB64 = arrayBufferToBase64(arrPassword);
                const ivB64 = arrayBufferToBase64(ivArrPass);
                backupForm.querySelector('input[name="b64Pass"]').value = passB64
                passwordField.value = '';
                backupForm.querySelector('input[name="ivPass"]').value = ivB64;
                showToast('Please test backup with the password you provided');
                isFormSubmitted = true;
                backupForm.submit();
            } else {
                showToast('Required information is missing, please check your input and try again.');
            }
        }
    });
});

document.addEventListener('DOMContentLoaded', () => {
    let isFormSubmitted = false; 
    const csvForm = document.getElementById('csvForm'); // Ensure your form has this ID
    csvForm.addEventListener('submit', async function(e) {
        if (!isFormSubmitted) {
            e.preventDefault();
            const fileInput = document.getElementById('csvFile');
            const file = fileInput.files[0];
            const encKey = await getDek().catch(error => {
                console.error('Error fetching encryption key');
                showToast('Error fetching encryption key');
                return null;
            });
            if (file && encKey) {
                const { encryptedDataB64: fileB64, ivB64: ivFileB64 } = await encryptFileAndB64(encKey.dek, file).catch(error => {
                    console.error('Error encrypting file');
                    showToast('Error encrypting file');
                    return null;
                });
                if (fileB64 && ivFileB64) {
                    showToast('Your upload is being uploaded');
                    csvForm.querySelector('input[name="encFileB64"]').value = fileB64;
                    csvForm.querySelector('input[name="ivFileB64"]').value = ivFileB64;
                    // Clear the original file input or remove it from the form
                    fileInput.value = '';
                    isFormSubmitted = true;
                    csvForm.submit();
                }
            };
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
        console.error("Failed to encrypt file");
        throw error; // Rethrow to handle the error externally
    }
}


async function encryptFileAndB64(aesKey, file) {
    const { encryptedData, iv } = await encryptFileWithAesGcm(aesKey, file);

    // Prepare data to send
    const encryptedDataB64 = arrayBufferToBase64(encryptedData);
    const ivB64 = arrayBufferToBase64(iv);

    return { encryptedDataB64, ivB64}
}