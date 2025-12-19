// public/js/main.js
document.addEventListener('click', (event) => {
  const button = document.getElementById('moreMenuButton');
  const dropdown = document.getElementById('moreDropdown');

  if (!button || !dropdown) return;

  // Click on the three dots - toggle dropdown
  if (button.contains(event.target)) {
    dropdown.classList.toggle('is-open');
    return;
  }

  // Click anywhere else - close dropdown
  if (!dropdown.contains(event.target)) {
    dropdown.classList.remove('is-open');
  }
});
