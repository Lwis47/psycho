(() => {
  const toggle = document.getElementById("navToggle");
  const nav = document.getElementById("siteNav");

  if (toggle && nav) {
    const closeMenu = () => {
      nav.classList.remove("nav-open");
      toggle.setAttribute("aria-expanded", "false");
    };

    toggle.addEventListener("click", () => {
      const isOpen = nav.classList.toggle("nav-open");
      toggle.setAttribute("aria-expanded", String(isOpen));
    });

    nav.querySelectorAll("a").forEach((link) => link.addEventListener("click", closeMenu));
    document.addEventListener("click", (event) => {
      if (!nav.contains(event.target) && !toggle.contains(event.target)) closeMenu();
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        closeMenu();
        toggle.focus();
      }
    });
  }

  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  document.querySelectorAll("form[data-password-confirm]").forEach((form) => {
    const password = form.querySelector("[name='password'], [name='new_password']");
    const confirmation = form.querySelector("[name='confirm_password'], [name='confirm_new_password']");
    if (!password || !confirmation) return;

    const validate = () => {
      confirmation.setCustomValidity(password.value === confirmation.value ? "" : "Passwords do not match.");
    };
    password.addEventListener("input", validate);
    confirmation.addEventListener("input", validate);
  });
})();
