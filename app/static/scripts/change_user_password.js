async function generateAndEncryptDEK(password) {
    // Placeholder function to generate a DEK - in practice, this could be any secure, random value
    const dek = window.crypto.getRandomValues(new Uint8Array(16)); // For example, a 128-bit key

    // Derive KEK from the password
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        {"name": "PBKDF2"},
        false,
        ["deriveKey"]);

    const kek = await window.crypto.subtle.deriveKey(
        {
            "name": "PBKDF2",
            salt: enc.encode("boyah-baby"), // Use a unique salt for production
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { "name": "AES-GCM", "length": 256}, // KEK details
        true,
        [ "encrypt", "decrypt" ]);

    // Encrypt DEK with KEK
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Initialization vector for AES-GCM
    const encryptedDEK = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        kek,
        dek);

    return {encryptedDEK, iv, dek};
}

document.addEventListener('DOMContentLoaded', () => {
    let isFormSubmitted = false; // Flag to prevent infinite submission loop
    const form = document.getElementById('changePasswordForm');
    form.addEventListener('submit', async (e) => {
        if (!isFormSubmitted) {
        e.preventDefault();
            e.preventDefault(); // Prevent the form from submitting immediately if not already submitted by this script
            if (confirm('It is recommended that you backup all passwords using the backup utility in the dashboard, in case you forget your new master password. Do you want to proceed?')) {
                const currentPassword = document.querySelector('input[name="current_password"]').value;
                const newPassword = document.querySelector('input[name="new_password"]').value;
                const confirmPassword = document.querySelector('input[name="confirm_new_password"]').value;
                console.log(`${currentPassword} ${newPassword}`)

                if (newPassword === confirmPassword) {

                    try {
                        const hashedCurrentPassword = await hashPassword(currentPassword);
                        const hashedNewPassword = await hashPassword(newPassword);
                        const hashedConfirmPassword = await hashPassword(confirmPassword);
                        const { encryptedDEK, iv, dek } = await generateAndEncryptDEK(newPassword);

                        // Convert the ArrayBuffer to Base64
                        const encryptedDEKBase64 = arrayBufferToBase64(encryptedDEK);
                        const ivBase64 = arrayBufferToBase64(iv);
                        const dekBase64 = arrayBufferToBase64(dek);

                        // Populate the hidden fields
                        document.querySelector('input[name="encryptedDEK"]').value = encryptedDEKBase64;
                        document.querySelector('input[name="iv"]').value = ivBase64;
                        document.querySelector('input[name="current_password"]').value = hashedCurrentPassword;
                        document.querySelector('input[name="new_password"]').value = hashedNewPassword;
                        document.querySelector('input[name="confirm_new_password"]').value = hashedConfirmPassword;
                        document.querySelector('input[name="dek"]').value = dekBase64;
                        
                        // Indicate that the form is being submitted by this script
                        isFormSubmitted = true;
                        e.target.submit(); // Submit the form programmatically
                    } catch (error) {
                        console.error("Error during form preparation:", error);
                        alert("An error occurred during form preparation. Please try again.");
                    }
            } else {
                alert('Passwords do not match. Please try again.');
            }
            }
        }
    });
});


// Utility function to convert an ArrayBuffer to Base64
function arrayBufferToBase64(buffer) {
    var binary = '';
    var bytes = new Uint8Array(buffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

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