// Progressive clipboard enhancement; no credentials or review data leave this origin.
document.addEventListener('click', async (event) => {
  const button = event.target.closest('[data-copy]');
  if (!button) return;
  const input = document.getElementById(button.dataset.copy);
  try {
    await navigator.clipboard.writeText(input.value);
    button.textContent = 'Copied';
  } catch (_) {
    input.focus(); input.select();
    button.textContent = 'Selected — touch and hold to copy';
  }
});
