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
function togglePasswordVisibility() {
    var passwordField = document.getElementById('password');
    var passwordToggle = document.getElementById('showPassword');
    if (passwordToggle.checked) {
        passwordField.type = 'text';
    } else {
        passwordField.type = 'password';
    }
}