// function generatePassword(length) {
//     var charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+<>?";
//     var password = "";
//     for (var i = 0, n = charset.length; i < length; ++i) {
//         password += charset.charAt(Math.floor(Math.random() * n));
//     }
//     return password;
// }
// function generateSecureRandomNumber() {
//     var array = new Uint32Array(1);
//     window.crypto.getRandomValues(array);
//     return array[0];
// }
function generatePassword(length) {
    var charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+<>?";
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