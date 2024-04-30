import {arrayBufferToBase64, hashPassword, generateAndEncryptDEK} from './utils.js';


document.addEventListener('DOMContentLoaded', (event) => {
    let isFormSubmitted = false; // Flag to prevent infinite submission loop

    document.querySelector('form').addEventListener('submit', async (e) => {
        if (!isFormSubmitted) {
            e.preventDefault(); // Prevent the form from submitting immediately if not already submitted by this script

            const password = document.querySelector('input[name="password"]').value;
            const confirmPassword = document.querySelector('input[name="confirm_password"]').value;

            if (password === confirmPassword) {
                const username = document.querySelector('input[name="username"]').value;

                try {
                    const hashedPassword = await hashPassword(password);
                    const hashedConfirmPassword = await hashPassword(confirmPassword);
                    const { encryptedDEK, iv, salt } = await generateAndEncryptDEK(password);

                    // Convert the ArrayBuffer to Base64
                    const encryptedDEKBase64 = arrayBufferToBase64(encryptedDEK);
                    const ivBase64 = arrayBufferToBase64(iv);
                    const saltB64 = arrayBufferToBase64(salt);

                    // Populate the hidden fields
                    document.querySelector('input[name="encryptedDEK"]').value = encryptedDEKBase64;
                    document.querySelector('input[name="iv"]').value = ivBase64;
                    document.querySelector('input[name="saltB64"]').value = saltB64;
                    document.querySelector('input[name="username"]').value = username;
                    // Before submitting the form programmatically, clear the password fields
                    document.querySelector('input[name="password"]').value = hashedPassword;
                    document.querySelector('input[name="confirm_password"]').value = hashedConfirmPassword;
            
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
    });
});