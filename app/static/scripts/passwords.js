import { base64ToArrayBuffer, reEncryptDEKWithSharedSecret, importServerPublicKey,
         arrayBufferToBase64, keyPairGenerate, getSharedSecret, deriveAESKeyFromSharedSecret,
         keyExchangeShare, finalExchange, getDek, getEdek, decryptData,
         encryptStringWithAesGcm, importAesKeyFromBuffer} from './utils.js';


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


document.addEventListener('DOMContentLoaded', () => {
    let isFormSubmitted = false; // Flag to prevent infinite submission loop
    const {form, formType} = checkForm();

    async function encryptAndSetField(field, dek) {
        try {
            console.log('field: ', field.name, ' field value: ', field.value)
            const ivField = form.querySelector(`input[name="iv${field.name}"]`);
            console.log('ivField:', ivField)
            if (field.value !== '') {
                const { encryptedData, iv } = await encryptStringWithAesGcm(dek, field.value);
                console.log('iv: ', iv)
                field.value = arrayBufferToBase64(encryptedData);
                form.querySelector(`input[name="iv${field.name}"]`).value = arrayBufferToBase64(iv);
            }
        }catch (error) {
            console.error(`Encryption failed for ${field.name}: ${field.value}`, error);
        }
    };

    form.addEventListener('submit', async function(e) {
        if (!isFormSubmitted) {
            e.preventDefault();
            const fields = ['Name', 'Category', 'Username', 'Password'];
            if ((passwordVisibilityToggled === true && formType === 'editPass') || formType === 'addPass') {
                const encKey = await getDek();
                if (encKey) {
                    try {
                        for (const fieldName of fields) {
                            const field = form.querySelector(`input[name="${fieldName}"]`);
                            await encryptAndSetField(field, encKey.dek);
                        }
                        await encryptAndSetField(document.getElementById('notes'), encKey.dek);
                    } catch (error) {
                        console.error('Encryption failed', error);
                        return;
                    }
                    isFormSubmitted = true;
                    form.submit();
                } else {
                    console.error('Failed to retrieve DEK');
                    return;
                }
            }
        }
    })
})
