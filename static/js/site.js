(() => {
  const root = document.documentElement;
  const themeToggle = document.querySelector("[data-theme-toggle]");
  const savedTheme = window.localStorage.getItem("ehh-theme");
  if (savedTheme === "light" || savedTheme === "dark") root.dataset.theme = savedTheme;
  const updateThemeLabel = () => {
    if (themeToggle) themeToggle.querySelector("[data-theme-label]").textContent =
      root.dataset.theme === "light" ? "Dark mode" : "Light mode";
  };
  updateThemeLabel();
  themeToggle?.addEventListener("click", () => {
    root.dataset.theme = root.dataset.theme === "light" ? "dark" : "light";
    window.localStorage.setItem("ehh-theme", root.dataset.theme);
    updateThemeLabel();
  });

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

  const pathSearch = document.querySelector("[data-path-search]");
  const pathCards = [...document.querySelectorAll("[data-path-card]")];
  const pathEmpty = document.querySelector("[data-path-empty]");
  pathSearch?.addEventListener("input", () => {
    const query = pathSearch.value.trim().toLowerCase();
    let visible = 0;
    pathCards.forEach((card) => {
      const matches = card.dataset.search.toLowerCase().includes(query);
      card.hidden = !matches;
      if (matches) visible += 1;
    });
    if (pathEmpty) pathEmpty.hidden = visible > 0;
  });

  document.querySelectorAll("[data-tabs]").forEach((tabs) => {
    const buttons = [...tabs.querySelectorAll("[data-tab]")];
    const panels = [...tabs.querySelectorAll("[data-panel]")];
    buttons.forEach((button) => button.addEventListener("click", () => {
      buttons.forEach((item) => {
        const active = item === button;
        item.classList.toggle("is-active", active);
        item.setAttribute("aria-selected", String(active));
      });
      panels.forEach((panel) => {
        panel.hidden = panel.dataset.panel !== button.dataset.tab;
        panel.classList.toggle("is-active", !panel.hidden);
      });
    }));
  });
})();
