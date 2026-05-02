import { djangoSecretKey } from './generators.js';

const generators = {
  'django-secret': djangoSecretKey,
};

class KeyCard {
  constructor(el) {
    this.el = el;
    this.kind = el.dataset.card;
    this.valueEl = el.querySelector('.card-value');
    this.gen = generators[this.kind];
    if (!this.gen) return;

    this.regenerate({ animate: false });

    el.addEventListener('click', this.onClick);
    el.addEventListener('keydown', this.onKeyDown);
    this.valueEl.addEventListener('animationend', () => {
      this.valueEl.classList.remove('flash');
    });
    el.addEventListener('animationend', (e) => {
      if (e.animationName === 'card-pulse') el.classList.remove('copied');
    });
  }

  onClick = (e) => {
    // Allow controls inside the card (sliders, toggles) to act without triggering regen.
    if (e.target.closest('.card-config')) return;
    this.regenerateAndCopy();
  };

  onKeyDown = (e) => {
    if (e.target !== this.el) return;
    if (e.key === ' ' || e.key === 'Enter' || e.key === 'r' || e.key === 'R') {
      e.preventDefault();
      this.regenerateAndCopy();
    } else if (e.key === 'c' || e.key === 'C') {
      e.preventDefault();
      this.copy();
    }
  };

  regenerate({ animate = true } = {}) {
    this.value = this.gen();
    this.valueEl.textContent = this.value;
    if (animate) {
      this.valueEl.classList.remove('flash');
      // force reflow so the animation can re-trigger on rapid presses
      void this.valueEl.offsetWidth;
      this.valueEl.classList.add('flash');
    }
  }

  regenerateAndCopy() {
    this.regenerate();
    this.copy();
  }

  async copy() {
    try {
      await navigator.clipboard.writeText(this.value);
      this.flashCopied();
    } catch (err) {
      // Clipboard write can fail outside a user gesture or in insecure contexts.
      console.warn('Clipboard write failed', err);
    }
  }

  flashCopied() {
    this.el.classList.remove('copied');
    void this.el.offsetWidth;
    this.el.classList.add('copied');
  }
}

// Wire cards
for (const el of document.querySelectorAll('.card')) new KeyCard(el);

// ---------- Theme ----------
const THEME_KEY = 'keysmith.theme';
const root = document.documentElement;
if (!root.dataset.theme) root.dataset.theme = 'dark';

const themeToggle = document.querySelector('.theme-toggle');
themeToggle.addEventListener('click', toggleTheme);

function toggleTheme() {
  const next = root.dataset.theme === 'dark' ? 'light' : 'dark';
  root.dataset.theme = next;
  try {
    localStorage.setItem(THEME_KEY, next);
  } catch {}
}

// ---------- Global shortcuts ----------
const filter = document.querySelector('.filter');

document.addEventListener('keydown', (e) => {
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  const tag = e.target?.tagName;
  const inField = tag === 'INPUT' || tag === 'TEXTAREA' || e.target?.isContentEditable;

  if (e.key === '/' && !inField) {
    e.preventDefault();
    filter?.focus();
    filter?.select();
    return;
  }
  if (e.key === 'Escape' && document.activeElement === filter) {
    filter.blur();
    return;
  }
  if ((e.key === 't' || e.key === 'T') && !inField) {
    toggleTheme();
  }
});
