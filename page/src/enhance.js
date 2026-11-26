// Progressive enhancement for Link in Bio pages. The page is complete without it: this only adds the colour-mode control and copy
// buttons. No network requests, no cookies, no tracking. A colour choice lasts for the visit; it is kept on this device only while the
// visitor ticks "Remember on this device", and unticking removes it (PECR Sch. A1 para 6; workspace docs/legal L-PECR-2).
//
// This file is compiled into the binary (crates/core/src/assets.rs), which removes every comment before serving it, so a visitor
// downloads only the code. For that to be safe a comment stays on a line of its own, never after code.
//
// Related: the markup it finds (`fieldset.mode`, `button.copy[data-copy]`) is written by crates/core/src/render.rs, and the rules
// that show the control once it is no longer `hidden` are in page.css. The browser tests are in e2e/page.spec.ts.

// The root element carries the colour mode as `data-theme`, which page.css reads.
const root = document.documentElement
// The one storage key, used only when the visitor asked to remember their choice.
const KEY = 'lib-color-mode'
// The values the key may hold; anything else is ignored, so a stale or tampered value cannot set an unknown theme.
const MODES = ['light', 'dark', 'system']

/**
 * The colour mode the visitor asked to keep on this device.
 * @returns {string | null} `light`, `dark` or `system`, or `null` when nothing valid is stored or storage is blocked
 */
function stored() {
  try {
    const v = localStorage.getItem(KEY)
    return MODES.includes(v) ? v : null
  } catch {
    // Storage can be blocked (a private window, a policy); then nothing was kept.
    return null
  }
}

/**
 * Keep a colour mode on this device, or forget it.
 * @param {string | null} mode - the mode to keep, or `null` to remove what is kept
 * @returns {void}
 */
function store(mode) {
  try {
    if (mode === null) localStorage.removeItem(KEY)
    else localStorage.setItem(KEY, mode)
  } catch {
    // Storage may be blocked; the choice then lasts for this visit only.
  }
}

// The colour-mode control is in the markup but hidden; it is shown below, so a visitor without scripts never sees a dead control.
const control = document.querySelector('fieldset.mode')
if (control) {
  // One button per mode, each carrying its mode in `data-mode`.
  const buttons = [...control.querySelectorAll('button[data-mode]')]
  // The "Remember on this device" checkbox.
  const remember = control.querySelector('input[name="remember"]')
  // The mode now showing, so ticking the box later can keep it.
  let current = null
  /**
   * Show a mode: set it on the page and mark its button as the pressed one.
   * @param {string} mode - `light`, `dark` or `system`
   * @returns {void}
   */
  const show = (mode) => {
    current = mode
    root.setAttribute('data-theme', mode)
    // `aria-pressed` tells assistive technology which button is on; the stylesheet draws the same state.
    for (const b of buttons) b.setAttribute('aria-pressed', String(b.dataset.mode === mode))
  }
  // A kept choice wins; otherwise the mode the server rendered; otherwise follow the system.
  const initial = stored()
  show(initial ?? root.getAttribute('data-theme') ?? 'system')
  // A stored choice is one the visitor asked to keep, so the box starts ticked only then.
  if (remember) remember.checked = initial !== null
  for (const b of buttons) {
    b.addEventListener('click', () => {
      // A choice applies at once; it is written to storage only while the box is ticked.
      show(b.dataset.mode)
      if (remember?.checked) store(b.dataset.mode)
    })
  }
  // Ticking keeps the current mode; unticking removes it, so nothing stays after the visitor withdraws the request.
  remember?.addEventListener('change', () => store(remember.checked ? current : null))
  // Only now is the control shown.
  control.hidden = false
}

// Copy buttons need the clipboard; without it they stay hidden and the address stays selectable text.
if (navigator.clipboard) {
  for (const button of document.querySelectorAll('button.copy[data-copy]')) {
    // The label to restore after the confirmation.
    const label = button.textContent
    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(button.dataset.copy)
        button.textContent = 'Copied'
      } catch {
        // The browser refused (no permission, or an insecure context): say so, and point to the selectable text.
        button.textContent = 'Copy failed: select the address instead'
      }
      // Put the label back after two seconds.
      setTimeout(() => {
        button.textContent = label
      }, 2000)
    })
    button.hidden = false
  }
}
