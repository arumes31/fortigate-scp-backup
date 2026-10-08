document.addEventListener('DOMContentLoaded', function () {
    var input = document.getElementById('query');
    document.querySelectorAll('.chip').forEach(function (chip) {
        chip.addEventListener('click', function () {
            if (!input) { return; }
            input.value = this.dataset.q;
            input.focus();
        });
    });
});
