import { base64ToArrayBuffer, getDek, decryptData,decryptField} from './utils.js';


async function updateTableWithData(data) {
    const enKey = await getDek();
    // In python, the data structure needs to be {id: [1,2,3,4], Name: [a,b,c,d]....}
    const tableBody = document.getElementById('myTable').getElementsByTagName('tbody')[0];
    const length = data.id.length;
    for (let i = 0; i < length; i++) {
        let name = await decryptField(enKey.dek, data.Name[i], data.ivName[i]);
        let username = await decryptField(enKey.dek, data.Username[i], data.ivUsername[i]);
        let category = await decryptField(enKey.dek, data.Category[i], data.ivCategory[i]);
        const row = tableBody.insertRow();
        row.innerHTML = `
            <td>${name}</td>
            <td>${username}</td>
            <td>${category}</td>
            <td>
                <button type="button" class="edit-btn" data-edit-url="/edit_password/${data.id[i]}">Edit</button>
                <button type="button" class="copy-to-clipboard-btn" data-password-id="${data.id[i]}">Copy to Clipboard</button>
                <button type="button" class="delete-btn" data-password-id="${data.id[i]}">Delete</button>
            </td>
            <td class="checkbox-cell"><input type="checkbox" name="selected_passwords" value="${data.id[i]}"></td>
        `;
    }
}


async function copyToClipboard(passwordId) {
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

    try {
        const response = await fetch('/decrypt_password/' + passwordId, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({ passwordId: passwordId })
        });

        if (!response.ok) {
            throw new Error('Network response was not ok.');
        }

        const data = await response.json();
        const encKey = await getDek();
        const ivArr = base64ToArrayBuffer(data.iv);
        const passArr = base64ToArrayBuffer(data.password);
        const passwordDecrypted = await decryptData(encKey.dek, passArr, ivArr);
        const decoder = new TextDecoder('utf-8');
        const password = decoder.decode(passwordDecrypted);

        if (navigator.clipboard) {
            try {
                await navigator.clipboard.writeText(password);
                showToast('Password copied to clipboard successfully!');
            } catch (err) {
                console.error('Failed to copy with Clipboard API: ', err);
                showToast('Failed to copy password to clipboard.');
            }
        } else {
            fallbackCopyTextToClipboard(password);
        }
    } catch (error) {
        console.error('Error:', error);
        showToast('Failed to fetch or decrypt the password.');
    }
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
document.addEventListener('DOMContentLoaded', async function() {
    var encryptedDataElement = document.getElementById('vaultData');
    var encryptedData = encryptedDataElement.dataset.vault;

    // Assuming decryptData is your function to decrypt the data
    //const decryptedData = decryptData(encryptedData);  // You will need to define this function based on your encryption

    if (encryptedData && encryptedData !== "{}") {
        await updateTableWithData(JSON.parse(encryptedData));
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


    var deleteButtons = document.querySelectorAll('.delete-btn');
    deleteButtons.forEach(function(button) {
      button.addEventListener('click', function() {
        var passwordId = this.getAttribute('data-password-id');
        var form = document.createElement('form');
        form.style.display = 'none';
        form.method = 'POST';
  
        // Construct the URL for the Flask route directly
        form.action = '/delete_password/' + passwordId;
  
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
