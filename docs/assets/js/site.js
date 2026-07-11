(() => {
  for (const button of document.querySelectorAll(".copy-button")) {
    button.addEventListener("click", async () => {
      const target = button.closest(".install-box")?.querySelector("code");
      if (!target) return;
      const value = target.textContent.trim();
      let copied = false;
      try {
        if (navigator.clipboard) {
          await navigator.clipboard.writeText(value);
          copied = true;
        }
      } catch (_) {
        // Fall through to the local selection-based copy path.
      }
      if (!copied) {
        const input = document.createElement("textarea");
        input.value = value;
        input.setAttribute("readonly", "");
        input.style.position = "fixed";
        input.style.opacity = "0";
        document.body.appendChild(input);
        input.select();
        copied = document.execCommand("copy");
        input.remove();
      }
      const original = button.textContent;
      button.textContent = copied ? "Copied" : "Select command";
      setTimeout(() => { button.textContent = original; }, 1400);
    });
  }
})();
