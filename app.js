import * as G from './generators.js';

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
};

class KeyCard {
  constructor(el) {
    this.el = el;
    this.kind = el.dataset.card;
    this.valueEl = el.querySelector('.card-value');
    this.gen = generators[this.kind];
    this.options = {};
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
          this.regenerate();
        });
      }
    }

    // Native inputs with data-control
    const inputs = this.el.querySelectorAll('input[data-control], textarea[data-control]');
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
      const evt = ctrl.type === 'checkbox' ? 'change' : 'input';
      ctrl.addEventListener(evt, () => {
        update();
        this.regenerate();
      });
      // prevent space/enter on inputs from triggering card regen
      ctrl.addEventListener('keydown', (e) => e.stopPropagation());
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
  regenerate({ animate = true } = {}) {
    try {
      this.value = this.gen(this.options);
    } catch (err) {
      console.warn(`[${this.kind}] generation failed`, err);
      return;
    }
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
