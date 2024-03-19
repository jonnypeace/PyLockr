function copyToClipboard(passwordId) {
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

    fetch('/decrypt_password/' + passwordId, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken, // Here you set the CSRF token in the request headers
        },
        body: JSON.stringify({ passwordId: passwordId }) // If your backend expects JSON, ensure to send the passwordId in the body
    })
    .then(response => response.json()) // Parse the JSON response
    .then(data => {
        // Extract the password from the parsed JSON object
        const password = data.password;
        // Use the Clipboard API to copy the extracted password
        if (navigator.clipboard) {
            navigator.clipboard.writeText(password).then(() => {
                showToast();
            }).catch(err => {
                console.error('Failed to copy with Clipboard API: ', err);
            });
        } else {
            fallbackCopyTextToClipboard(password); // Use the fallback method with the extracted password
        }
    })
    .catch(error => console.error('Error:', error));
}

// Fallback method using execCommand for older browsers
function fallbackCopyTextToClipboard(text) {
    var textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    try {
        var successful = document.execCommand('copy');
        var msg = successful ? 'successful' : 'unsuccessful';
        console.log('Fallback: Copying text command was ' + msg);
        showToast();
    } catch (err) {
        console.error('Fallback: Oops, unable to copy', err);
    }
    document.body.removeChild(textarea);
}

function showToast() {
    var toast = document.getElementById("toast");
    toast.style.display = "block";
    setTimeout(function() { toast.style.display = "none"; }, 3000); // Hide after 3 seconds
}

new DataTable('#myTable', {
    responsive: true,
    scroller: true,
    scrollY: 400,
    deferRender: true,
    scroller: {
        displayBuffer: 10 // Adjust this value to preload more rows
    }
});

// Multi Select Delete all button listener
document.addEventListener('DOMContentLoaded', () => {
    const deleteButtons = document.querySelectorAll('.delete-confirm-btn');
    deleteButtons.forEach(button => {
        button.addEventListener('click', (event) => {
            const isConfirmed = confirm('Are you sure you want to delete this?');
            if (!isConfirmed) {
                event.preventDefault();
            }
        });
    });
});

// Event delegation for the Delete button
document.addEventListener('DOMContentLoaded', function() {
    var deleteButtons = document.querySelectorAll('.delete-btn');
    deleteButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            var passwordId = this.getAttribute('data-password-id');
            var form = document.createElement('form');
            form.style.display = 'none';
            form.method = 'POST';
            // Flask application's URL structure for processing password_id
            form.action = "{{ url_for('main.delete_password', password_id=0) }}".replace('/0', '/' + passwordId);

            // CSRF Token
            var csrfInput = document.createElement('input');
            csrfInput.type = 'hidden';
            csrfInput.name = 'csrf_token';
            csrfInput.value = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

            form.appendChild(csrfInput);

            document.body.appendChild(form);
            if (confirm('Are you sure you want to delete this password?')) {

                form.submit();
            }
        });
    });
});


// Select All Button
$('#selectAllBtn').on('click', function() {
    $('#myTable tbody input[type="checkbox"]').prop('checked', true);
});

// Deselect All Button
$('#deselectAllBtn').on('click', function() {
    $('#myTable tbody input[type="checkbox"]').prop('checked', false);
});

// Event delegation for the Copy to Clipboard button
$('#myTable tbody').on('click', '.copy-to-clipboard-btn', function () {
    var passwordId = $(this).data('password-id');
    copyToClipboard(passwordId); // Make sure the function name matches
});

// Event delegation for the Edit button
$('#myTable tbody').on('click', '.edit-btn', function () {
    var editUrl = $(this).data('edit-url');
    window.location.href = editUrl; // Redirect to the edit URL
});
