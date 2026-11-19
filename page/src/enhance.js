// Progressive enhancement for Link in Bio pages. The page is complete without it: this only adds the colour-mode control and copy
// buttons. No network requests, no cookies, no tracking. A colour choice lasts for the visit; it is kept on this device only while the
// visitor ticks "Remember on this device", and unticking removes it (PECR Sch. A1 para 6; workspace docs/legal L-PECR-2).
const root = document.documentElement
const KEY = 'lib-color-mode'
const MODES = ['light', 'dark', 'system']

function stored() {
  try {
    const v = localStorage.getItem(KEY)
    return MODES.includes(v) ? v : null
  } catch {
    return null
  }
}

function store(mode) {
  try {
    if (mode === null) localStorage.removeItem(KEY)
    else localStorage.setItem(KEY, mode)
  } catch {
    // Storage may be blocked; the choice then lasts for this visit only.
  }
}

const control = document.querySelector('fieldset.mode')
if (control) {
  const buttons = [...control.querySelectorAll('button[data-mode]')]
  const remember = control.querySelector('input[name="remember"]')
  let current = null
  const show = (mode) => {
    current = mode
    root.setAttribute('data-theme', mode)
    for (const b of buttons) b.setAttribute('aria-pressed', String(b.dataset.mode === mode))
  }
  const initial = stored()
  show(initial ?? root.getAttribute('data-theme') ?? 'system')
  // A stored choice is one the visitor asked to keep, so the box starts ticked only then.
  if (remember) remember.checked = initial !== null
  for (const b of buttons) {
    b.addEventListener('click', () => {
      show(b.dataset.mode)
      if (remember?.checked) store(b.dataset.mode)
    })
  }
  remember?.addEventListener('change', () => store(remember.checked ? current : null))
  control.hidden = false
}

if (navigator.clipboard) {
  for (const button of document.querySelectorAll('button.copy[data-copy]')) {
    const label = button.textContent
    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(button.dataset.copy)
        button.textContent = 'Copied'
      } catch {
        button.textContent = 'Copy failed: select the address instead'
      }
      setTimeout(() => {
        button.textContent = label
      }, 2000)
    })
    button.hidden = false
  }
}
