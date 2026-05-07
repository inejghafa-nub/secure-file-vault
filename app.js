const password = document.querySelector('#password');

if (password) {
    const rules = {
        'length-rule': value => value.length >= 8,
        'upper-rule': value => /[A-Z]/.test(value),
        'lower-rule': value => /[a-z]/.test(value),
        'number-rule': value => /\d/.test(value),
        'special-rule': value => /[^A-Za-z0-9]/.test(value),
    };

    password.addEventListener('input', () => {
        Object.entries(rules).forEach(([id, test]) => {
            const item = document.getElementById(id);
            item.classList.toggle('passed', test(password.value));
        });
    });
}
