import * as G from './generators.js';
import * as C from './crypto.js';

const generators = {
  'django-secret': G.djangoSecretKey,
  'django-fernet': G.djangoFernetKey,
  'flask-secret': G.flaskSecretKey,
  'rails-secret': G.railsSecretKeyBase,
  'laravel-app-key': G.laravelAppKey,
  'nextauth-secret': G.nextAuthSecret,
  jwt: G.jwtSecret,
  encryption: G.encryptionKey,
  'api-key': G.apiKey,
  'webhook-secret': G.webhookSecret,
  'uuid-v4': G.uuidv4,
  'uuid-v7': G.uuidv7,
  'nano-id': G.nanoId,
  ulid: G.ulid,
  'mongo-objectid': G.mongoObjectId,
  password: G.password,
  pin: G.pin,
  custom: G.customRandom,
  // Input-driven transforms (data-mode="transform"): hash / encrypt your own text.
  hash: C.hashText,
  cipher: C.cipherText,
};

class KeyCard {
  constructor(el) {
    this.el = el;
    this.kind = el.dataset.card;
    this.valueEl = el.querySelector('.card-value');
    this.gen = generators[this.kind];
    this.options = {};
    this.value = '';
    // Transform cards take user input and run async crypto on an explicit action
    // (Run button / Enter / clicking the card) rather than on every keystroke.
    this.isTransform = el.dataset.mode === 'transform';
    this.requires = (el.dataset.requires || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    this.placeholder = el.dataset.placeholder || '—';
    this.runToken = 0;
    if (!this.gen) return;

    this.bindControls();
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

  // ---------- Controls ----------
  bindControls() {
    // Segmented (radiogroup) controls — buttons with data-value, container has data-control
    const segments = this.el.querySelectorAll('[data-type="segmented"]');
    for (const group of segments) {
      const name = group.dataset.control;
      const buttons = [...group.querySelectorAll('button')];
      const initial = buttons.find((b) => b.getAttribute('aria-pressed') === 'true') ?? buttons[0];
      this.options[name] = coerce(initial?.dataset.value);
      for (const btn of buttons) {
        btn.addEventListener('click', (e) => {
          e.preventDefault();
          for (const b of buttons) b.setAttribute('aria-pressed', b === btn ? 'true' : 'false');
          this.options[name] = coerce(btn.dataset.value);
          // Transform cards wait for an explicit Run; others update live.
          if (!this.isTransform) this.regenerate();
        });
      }
    }

    // Native inputs with data-control (input / textarea / select)
    const inputs = this.el.querySelectorAll(
      'input[data-control], textarea[data-control], select[data-control]',
    );
    for (const ctrl of inputs) {
      const name = ctrl.dataset.control;
      const display = ctrl.parentElement?.querySelector('.config-value');
      const update = () => {
        if (ctrl.type === 'checkbox') this.options[name] = ctrl.checked;
        else if (ctrl.type === 'range' || ctrl.type === 'number')
          this.options[name] = Number(ctrl.value);
        else this.options[name] = ctrl.value;
        if (display && (ctrl.type === 'range' || ctrl.type === 'number')) {
          display.textContent = ctrl.value;
        }
      };
      update();

      if (this.isTransform) {
        // Keep options current, but don't recompute on every keystroke.
        const evt = ctrl.tagName === 'SELECT' || ctrl.type === 'checkbox' ? 'change' : 'input';
        ctrl.addEventListener(evt, update);
      } else {
        const evt = ctrl.type === 'checkbox' ? 'change' : 'input';
        ctrl.addEventListener(evt, () => {
          update();
          this.regenerate();
        });
      }

      ctrl.addEventListener('keydown', (e) => {
        e.stopPropagation(); // don't let space/enter bubble to the card
        // Enter in a single-line field runs the transform (textarea keeps newlines).
        if (this.isTransform && e.key === 'Enter' && ctrl.tagName !== 'TEXTAREA') {
          e.preventDefault();
          this.regenerateAndCopy();
        }
      });
    }

    // Explicit run/copy buttons (Hash / Run) on transform cards.
    for (const btn of this.el.querySelectorAll('[data-action="run"]')) {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        this.regenerateAndCopy();
      });
      btn.addEventListener('keydown', (e) => e.stopPropagation());
    }
  }

  // ---------- Events ----------
  onClick = (e) => {
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

  // ---------- Behavior ----------
  hasRequiredInput() {
    return this.requires.every((k) => {
      const v = this.options[k];
      return typeof v === 'string' ? v.trim().length > 0 : v != null;
    });
  }

  setOutput(text, stateClass) {
    this.valueEl.textContent = text;
    this.valueEl.classList.remove('is-hint', 'is-error');
    if (stateClass) this.valueEl.classList.add(stateClass);
  }

  async regenerate({ animate = true } = {}) {
    // Transform cards with missing input just show their prompt.
    if (this.isTransform && !this.hasRequiredInput()) {
      this.el.classList.remove('busy');
      this.value = '';
      this.setOutput(this.placeholder, 'is-hint');
      return;
    }

    const token = ++this.runToken;
    if (this.isTransform) {
      this.el.classList.add('busy');
      this.setOutput('Computing…', 'is-hint');
    }

    let result;
    try {
      result = await this.gen(this.options);
    } catch (err) {
      if (token !== this.runToken) return; // a newer run superseded this one
      this.el.classList.remove('busy');
      this.value = '';
      this.setOutput('⚠ ' + (err?.message || 'Something went wrong'), 'is-error');
      return;
    }
    if (token !== this.runToken) return;

    this.el.classList.remove('busy');
    this.value = result;
    this.setOutput(result, null);
    if (animate) {
      this.valueEl.classList.remove('flash');
      // force reflow so the animation can re-trigger on rapid presses
      void this.valueEl.offsetWidth;
      this.valueEl.classList.add('flash');
    }
  }

  async regenerateAndCopy() {
    await this.regenerate();
    if (this.value) await this.copy();
  }

  async copy() {
    if (!this.value) return;
    try {
      await navigator.clipboard.writeText(this.value);
      this.flashCopied();
    } catch (err) {
      console.warn('Clipboard write failed', err);
    }
  }

  flashCopied() {
    this.el.classList.remove('copied');
    void this.el.offsetWidth;
    this.el.classList.add('copied');
  }
}

function coerce(v) {
  if (v === undefined || v === null) return v;
  if (v === 'true') return true;
  if (v === 'false') return false;
  if (/^-?\d+$/.test(v)) return Number(v);
  return v;
}

// ---------- Boot ----------
const cards = [...document.querySelectorAll('.card')].map((el) => new KeyCard(el));

// Filter
const filter = document.querySelector('.filter');
filter?.addEventListener('input', () => {
  const q = filter.value.trim().toLowerCase();
  for (const card of cards) {
    if (!card.el) continue;
    const haystack = (card.el.textContent + ' ' + (card.kind ?? '')).toLowerCase();
    const match = !q || haystack.includes(q);
    card.el.classList.toggle('hidden', !match);
  }
  // Hide section headers whose grids are empty.
  for (const sec of document.querySelectorAll('.section')) {
    const visible = sec.querySelectorAll('.card:not(.hidden)').length;
    sec.classList.toggle('hidden', visible === 0);
  }
});

// Theme
const THEME_KEY = 'keysmith.theme';
const root = document.documentElement;
if (!root.dataset.theme) root.dataset.theme = 'dark';
const themeToggle = document.querySelector('.theme-toggle');
themeToggle?.addEventListener('click', toggleTheme);

function toggleTheme() {
  const next = root.dataset.theme === 'dark' ? 'light' : 'dark';
  root.dataset.theme = next;
  try {
    localStorage.setItem(THEME_KEY, next);
  } catch {}
}

// Global shortcuts
document.addEventListener('keydown', (e) => {
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  const tag = e.target?.tagName;
  const inField = tag === 'INPUT' || tag === 'TEXTAREA' || e.target?.isContentEditable;
  if (e.key === '/' && !inField) {
    e.preventDefault();
    filter?.focus();
    filter?.select();
  } else if (e.key === 'Escape' && document.activeElement === filter) {
    filter.blur();
  } else if ((e.key === 't' || e.key === 'T') && !inField) {
    toggleTheme();
  }
});
