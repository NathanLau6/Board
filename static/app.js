document.addEventListener("DOMContentLoaded", function() {
    document.querySelectorAll("form[action^='/like/']").forEach(form => {
        form.addEventListener("submit", function(event) {
            event.preventDefault();
            fetch(form.action, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                }
            }).then(response => {
                if (response.ok) {
                    return response.json();
                } else {
                    return response.json().then(error => { throw new Error(error.error); });
                }
            }).then(data => {
                form.previousElementSibling.textContent = `${data.likes} likes`;
            }).catch(error => {
                alert(error.message);
            });
        });
    });
});
