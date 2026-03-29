document.addEventListener("DOMContentLoaded", () => {
  const keywordInput = document.querySelector('input[name="keyword"]');
  if (keywordInput) {
    keywordInput.focus();
  }

  const searchForm = document.querySelector('form[action="/"][method="GET"], form[action="/"][method="get"]');
  if (!searchForm) {
    return;
  }

  searchForm.addEventListener("submit", (event) => {
    event.preventDefault();

    const params = new URLSearchParams();
    const formData = new FormData(searchForm);

    for (const [key, rawValue] of formData.entries()) {
      const value = String(rawValue).trim();
      if (value !== "") {
        params.append(key, value);
      }
    }

    const query = params.toString();
    window.location.href = query ? `/?${query}` : "/";
  });
});
