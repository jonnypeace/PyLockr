import { arrayBufferToBase64, generateAndEncryptDEK, encryptLoginPassword} from './utils.js';

document.addEventListener('DOMContentLoaded', () => {
    let isFormSubmitted = false; // Flag to prevent infinite submission loop
    const form = document.getElementById('changePasswordForm');
    form.addEventListener('submit', async (e) => {
        if (!isFormSubmitted) {
        e.preventDefault(); // Prevent the form from submitting immediately if not already submitted by this script
        if (confirm('It is RECOMMENDED that you BACKUP all passwords using the backup utility in the dashboard, in case you forget your new master password. Do you want to proceed?')) {
            const currentPassword = document.querySelector('input[name="current_password"]').value;
            const newPassword = document.querySelector('input[name="new_password"]').value;
            const confirmPassword = document.querySelector('input[name="confirm_new_password"]').value;

            if (newPassword === confirmPassword) {

                try {
                    if (confirm("Are you sure you want to proceed? PLEASE LOG BACK IN IMMEDIATELY TO COMPLETE THE PROCESS")) {
                        const encryptedCurrentPass = await encryptLoginPassword(currentPassword);
                        const encryptedNewPass = await encryptLoginPassword(newPassword);
                        const encryptedConfirmPass = await encryptLoginPassword(confirmPassword);
                        const { encryptedDEK, iv, salt } = await generateAndEncryptDEK(newPassword);

                        // Convert the ArrayBuffer to Base64
                        const encryptedDEKBase64 = arrayBufferToBase64(encryptedDEK);
                        const ivBase64 = arrayBufferToBase64(iv);
                        const saltBase64 = arrayBufferToBase64(salt);

                        // Populate the hidden fields
                        document.querySelector('input[name="encryptedDEK"]').value = encryptedDEKBase64;
                        document.querySelector('input[name="iv"]').value = ivBase64;
                        document.querySelector('input[name="salt"]').value = saltBase64;
                        document.querySelector('input[name="current_password"]').value = encryptedCurrentPass.encryptedPass;
                        document.querySelector('input[name="new_password"]').value = encryptedNewPass.encryptedPass;
                        document.querySelector('input[name="confirm_new_password"]').value = encryptedConfirmPass.encryptedPass;
                        
                        // Indicate that the form is being submitted by this script
                        isFormSubmitted = true;
                        e.target.submit(); // Submit the form programmatically
                    }
                } catch (error) {
                    console.error("Error during form preparation:");
                    alert("An error occurred during form preparation. Please try again.");
                }
        } else {
            alert('Passwords do not match. Please try again.');
        }}}
    });
});
