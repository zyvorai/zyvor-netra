// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
//
// Sets <html data-theme> before first paint. A file, not an inline script: the
// controller's Content-Security-Policy is script-src 'self'. Keep the rules in
// step with src/theme.ts (theme.test.ts runs both and compares them).
(function () {
  var preference = null;
  try {
    preference = localStorage.getItem('netra-appearance');
    // Before the Appearance menu, "light" was written on every visit, so only a
    // stored "dark" records a choice.
    if (!preference && localStorage.getItem('netra-theme') === 'dark') preference = 'dark';
  } catch (e) {
    /* storage unavailable: follow the system */
  }
  var theme =
    preference === 'light' || preference === 'dark'
      ? preference
      : window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light';
  document.documentElement.setAttribute('data-theme', theme);
  var meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', theme === 'dark' ? '#000000' : '#f5f5f7');
})();
