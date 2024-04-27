import {arrayBufferToBase64, hashPassword} from './utils.js';

async function generateAndEncryptDEK(password) {
    // Placeholder function to generate a DEK - in practice, this could be any secure, random value
    const dek = window.crypto.getRandomValues(new Uint8Array(32)); // For a 256-bit key

    // Derive KEK from the password
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        {"name": "PBKDF2"},
        false,
        ["deriveKey"]);

    // Generate a unique salt for each key derivation
    const salt = window.crypto.getRandomValues(new Uint8Array(16));

    const kek = await window.crypto.subtle.deriveKey(
        {
            "name": "PBKDF2",
            salt: salt, // Use a unique salt for production
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

    return {encryptedDEK, iv, salt};
}

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