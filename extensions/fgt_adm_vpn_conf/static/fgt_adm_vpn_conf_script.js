document.addEventListener('DOMContentLoaded', function() {
    const editModal = document.getElementById('editModal');
    const closeButton = editModal.querySelector('.close-button');
    const modalBodyContent = document.getElementById('modal-body-content');
    const editLinks = document.querySelectorAll('.open-edit-modal');

    // Function to open the modal and load content
    editLinks.forEach(link => {
        link.addEventListener('click', function(event) {
            event.preventDefault();
            const configId = this.dataset.id;
            const editUrl = `/fgt-adm-vpn-conf/edit/${configId}`; // This is the new endpoint for the form

            fetch(editUrl)
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Network response was not ok');
                    }
                    return response.text();
                })
                .then(html => {
                    modalBodyContent.innerHTML = html;
                    editModal.style.display = 'block';

                    // Re-attach submit listener for the form inside the modal
                    const modalForm = modalBodyContent.querySelector('form');
                    if (modalForm) {
                        modalForm.addEventListener('submit', function(e) {
                            e.preventDefault();
                            fetch(modalForm.action, {
                                method: 'POST',
                                body: new FormData(modalForm)
                            })
                            .then(response => {
                                if (!response.ok) {
                                    return response.text().then(text => { throw new Error(text) });
                                }
                                return response.text(); // Assuming success returns a redirect or simple text
                            })
                            .then(data => {
                                alert('Configuration updated successfully!');
                                editModal.style.display = 'none';
                                window.location.reload(); // Reload the page to show updated data
                            })
                            .catch(error => {
                                console.error('Error updating configuration:', error);
                                alert('Error updating configuration: ' + error.message);
                            });
                        });
                    }
                })
                .catch(error => {
                    console.error('Error loading edit form:', error);
                    modalBodyContent.innerHTML = `<p>Error loading form: ${error.message}</p>`;
                    editModal.style.display = 'block'; // Still show modal to display error
                });
        });
    });

    // Function to close the modal
    closeButton.addEventListener('click', function() {
        editModal.style.display = 'none';
        modalBodyContent.innerHTML = ''; // Clear content when closing
    });

    // Close the modal if user clicks outside of it
    window.addEventListener('click', function(event) {
        if (event.target == editModal) {
            editModal.style.display = 'none';
            modalBodyContent.innerHTML = ''; // Clear content when closing
        }
    });

    // Collapsible section functionality
    const collapsibleHeader = document.querySelector('.collapsible-header');
    const collapsibleContent = document.querySelector('.collapsible-content');
    const toggleButton = document.querySelector('.collapsible-header .toggle-button');

    // Initially hide the content
    if (collapsibleContent) {
        collapsibleContent.style.display = 'none';
        if (toggleButton) {
            toggleButton.textContent = 'Show';
        }
    }

    if (collapsibleHeader) {
        collapsibleHeader.addEventListener('click', function(event) {
            // Check if the click originated from the toggle button itself
            if (event.target === toggleButton) {
                // Toggle button was clicked, prevent header from also triggering
                event.stopPropagation();
            }
            // Toggle the display of the content
            if (collapsibleContent) {
                if (collapsibleContent.style.display === 'none') {
                    collapsibleContent.style.display = 'block';
                    if (toggleButton) {
                        toggleButton.textContent = 'Hide';
                    }
                } else {
                    collapsibleContent.style.display = 'none';
                    if (toggleButton) {
                        toggleButton.textContent = 'Show';
                    }
                }
            }
        });
    }
});