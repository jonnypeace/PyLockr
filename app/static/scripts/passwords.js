import { base64ToArrayBuffer, reEncryptDEKWithSharedSecret, importServerPublicKey,
         arrayBufferToBase64, keyPairGenerate, getSharedSecret, deriveAESKeyFromSharedSecret,
         keyExchangeShare, finalExchange, getDek, getEdek, decryptData,
         encryptStringWithAesGcm, importAesKeyFromBuffer, decryptField} from './utils.js';


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
        passwordField.type = 'text';
    } else {
        passwordField.type = 'password';
    }
}

// This is for setting the fields before submitting form data to send to server
async function encryptAndSetField(form, field, dek) {
    try {
        const ivField = form.querySelector(`input[name="iv${field.name}"]`);
        if (field.value !== '') {
            const { encryptedData, iv } = await encryptStringWithAesGcm(dek, field.value);
            field.value = arrayBufferToBase64(encryptedData);
            form.querySelector(`input[name="iv${field.name}"]`).value = arrayBufferToBase64(iv);
        }
    }catch (error) {
        console.error(`Encryption failed for ${field.name}: ${field.value}`, error);
    }
};

// This is for the editPass form for viewing
async function updateEditPass(dek, data) {
    document.querySelector('input[name="Name"]').value = await decryptField(dek, data.Name, data.ivName);
    document.querySelector('input[name="Username"]').value = await decryptField(dek, data.Username, data.ivUsername);
    document.querySelector('input[name="Category"]').value = await decryptField(dek, data.Category, data.ivCategory);
    document.querySelector('input[name="Password"]').value = await decryptField(dek, data.Password, data.ivPassword);
    document.getElementById('notes').value = await decryptField(dek, data.Notes, data.ivNotes);
}

document.addEventListener('DOMContentLoaded', async () => {
    
    const encKey = await getDek();
    const {form, formType} = checkForm();

    // Updated and decrypt data into form fields 
    if (formType === 'editPass') {
        var encryptedDataElement = document.getElementById('vaultData');
        var encryptedData = encryptedDataElement.dataset.vault;
        console.log("Data to parse:", encryptedData);
        console.log("Type of data:", typeof encryptedData);
        const jsonData = JSON.parse(encryptedData);
        await updateEditPass(encKey.dek, jsonData);
    }

    let isFormSubmitted = false; // Flag to prevent infinite submission loop

    form.addEventListener('submit', async function(e) {
        if (!isFormSubmitted) {
            e.preventDefault();
            const fields = ['Name', 'Category', 'Username', 'Password'];
            if (encKey) {
                try {
                    for (const fieldName of fields) {
                        const field = form.querySelector(`input[name="${fieldName}"]`);
                        await encryptAndSetField(form, field, encKey.dek);
                    }
                    await encryptAndSetField(form, document.getElementById('notes'), encKey.dek);
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
    })
})
