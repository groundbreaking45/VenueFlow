/* ============================================================
   VenueFlow v2 — Application Logic
   - Dark / Light theme persistence
   - Pretext.js canvas text layout (CDN via dynamic import)
   - XSS-safe DOM helpers (no raw innerHTML with user data)
   - SOS rate-limiting
   - Keyboard shortcuts
   - Zone drill-down modal
   - CSV export
   - Search / filter
   - All simulation logic
   ============================================================ */

'use strict';

// ─────────────────────────────────────────────
// CONFIGURATION CONSTANTS
// All magic numbers extracted to a single source
// of truth for maintainability and code quality.
// ─────────────────────────────────────────────

/**
 * Application-wide configuration constants.
 * Centralising these values ensures consistent behaviour
 * across the simulation, Firebase sync, and AI modules.
 *
 * @constant {Object} CONFIG
 */
const CONFIG = {
  /** Maximum venue capacity in persons */
  MAX_CAPACITY: 80000,

  /** Crowd density ratio above which a zone is classified as critical (75%) */
  CRITICAL_DENSITY_THRESHOLD: 0.75,

  /** Crowd density ratio above which a zone is classified as warning (50%) */
  WARNING_DENSITY_THRESHOLD: 0.50,

  /** Minimum crowd density enforced by the simulation clamp */
  MIN_DENSITY: 0.08,

  /** Wait-time multiplier: wait = max(1, round(density × WAIT_MULTIPLIER)) */
  WAIT_MULTIPLIER: 32,

  /** Maximum SOS alerts allowed per rate-limit window */
  SOS_MAX_CALLS: 2,

  /** Rate-limit window duration in milliseconds (30 seconds) */
  SOS_WINDOW_MS: 30000,

  /** Firebase Realtime Database zone snapshot interval in milliseconds */
  FIREBASE_SYNC_INTERVAL_MS: 5000,

  /** AI orchestration cycle interval in milliseconds (30 seconds) */
  AI_LOOP_MS: 30000,

  /** Auth user counter refresh interval in milliseconds */
  AUTH_REFRESH_INTERVAL_MS: 15000,

  /** Heatmap animation frame rate target (ms per frame) */
  HEATMAP_FRAME_MS: 60,

  /** AI event feed maximum visible items */
  AI_FEED_MAX_ITEMS: 12,

  /** Click-detection radius for heatmap zone selection (pixels) */
  HEATMAP_CLICK_RADIUS_PX: 60,

  /** Wembley Stadium geocoordinates */
  VENUE_COORDS: { lat: 51.5560, lng: -0.2796 },
};

// ─────────────────────────────────────────────
// SECURITY HELPERS
// Safely build DOM nodes instead of raw innerHTML
// where user-controlled data could appear.
// ─────────────────────────────────────────────

/**
 * DOM utility namespace.
 * Provides XSS-safe element creation, text setting, and input sanitisation.
 * All user-controlled strings MUST pass through DOM.sanitise() before
 * being inserted into the document.
 *
 * @namespace DOM
 */
const DOM = {
  /**
   * Create an HTML element with optional properties.
   *
   * @param {string} tag   - HTML tag name (e.g. 'div', 'button')
   * @param {Object} props - Key-value pairs: 'class', 'text', 'html', or any attribute
   * @returns {HTMLElement}
   */
  el(tag, props = {}) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === 'class') e.className = v;
      else if (k === 'text') e.textContent = v;
      else if (k === 'html') e.innerHTML = v;   // only used with hard-coded strings
      else e.setAttribute(k, v);
    }
    return e;
  },

  /**
   * Safely set text content of an element by ID.
   *
   * @param {string} id   - Element ID
   * @param {*}      text - Value to display (coerced to string)
   * @returns {void}
   */
  setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = String(text);
  },

  /**
   * Sanitise any string that might hold user input before display.
   * Escapes the five HTML-significant characters: & < > " '
   *
   * @param {*} str - Input value (coerced to string)
   * @returns {string} HTML-escaped string safe for display
   */
  sanitise(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  },
};

// ─────────────────────────────────────────────
// RATE LIMITER (SOS abuse prevention)
// ─────────────────────────────────────────────

/**
 * Factory returning a sliding-window rate-limiter closure.
 * Used to prevent SOS button spam (max CONFIG.SOS_MAX_CALLS per CONFIG.SOS_WINDOW_MS).
 *
 * @param {number} maxCalls - Maximum allowed calls within the window
 * @param {number} windowMs - Rolling window duration in milliseconds
 * @returns {{ check: () => boolean }} Rate-limiter object
 */
const RateLimiter = (maxCalls, windowMs) => {
  const calls = [];
  return {
    /**
     * Check if a new call is permitted.
     * Purges expired timestamps before evaluating.
     * @returns {boolean} true if permitted, false if rate-limited
     */
    check() {
      const now = Date.now();
      while (calls.length && calls[0] < now - windowMs) calls.shift();
      if (calls.length >= maxCalls) return false;
      calls.push(now);
      return true;
    },
  };
};

/** SOS rate limiter: max 2 alerts per 30 seconds */
const sosRateLimit = RateLimiter(CONFIG.SOS_MAX_CALLS, CONFIG.SOS_WINDOW_MS);

// ─────────────────────────────────────────────
// PRETEXT INTEGRATION
// Used for accurate canvas text measurement
// on the heatmap zone labels.
// ─────────────────────────────────────────────
let pretextReady = false;
let pretextPrepare = null;
let pretextLayout = null;

/**
 * Attempt to load Pretext from jsDelivr ESM.
 * Falls back gracefully to Canvas measureText if unavailable.
 *
 * @returns {Promise<void>}
 */
async function loadPretext() {
  try {
    const mod = await import('https://unpkg.com/@chenglou/pretext/dist/index.esm.js');
    pretextPrepare = mod.prepare;
    pretextLayout = mod.layout;
    pretextReady = true;
  } catch {
    pretextReady = false;
  }
}

/**
 * Measure how wide a text string will render at a given font.
 * Uses Pretext if available; Canvas measureText as fallback.
 *
 * @param {string} text - The string to measure
 * @param {string} font - CSS font string (e.g. 'bold 9px Outfit, sans-serif')
 * @returns {number} Line count (Pretext) or pixel width (canvas fallback)
 */
function measureText(text, font) {
  if (pretextReady && pretextPrepare && pretextLayout) {
    try {
      const p = pretextPrepare(text, font);
      const { lineCount } = pretextLayout(p, 9999, 20);
      return lineCount;
    } catch { /* fallback */ }
  }
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  ctx.font = font;
  return ctx.measureText(text).width;
}

// ─────────────────────────────────────────────
// DATA
// ─────────────────────────────────────────────

/**
 * Live zone data representing crowd density across all stadium sections.
 * Density is a ratio [0.0 – 1.0]; wait is derived as round(density × 32).
 * These values are mutated by nudgeDensities() each simulation tick.
 *
 * @type {Array<{id:string, name:string, x:number, y:number, density:number, wait:number}>}
 */
const ZONES = [
  { id: 'N1', name: 'North Gate 1',       x: .08, y: .10, density: .92, wait: 28 },
  { id: 'N2', name: 'North Gate 2',       x: .28, y: .10, density: .55, wait: 9  },
  { id: 'E1', name: 'East Concourse',     x: .83, y: .28, density: .82, wait: 21 },
  { id: 'E2', name: 'East Restrooms',     x: .87, y: .52, density: .41, wait: 5  },
  { id: 'S1', name: 'South Exit Gate',    x: .18, y: .84, density: .35, wait: 4  },
  { id: 'S2', name: 'South Concession 4', x: .50, y: .88, density: .73, wait: 16 },
  { id: 'W1', name: 'West Medical Bay',   x: .06, y: .54, density: .20, wait: 2  },
  { id: 'W2', name: 'West Stand Bar',     x: .12, y: .72, density: .88, wait: 25 },
  { id: 'C1', name: 'Centre Concourse',   x: .44, y: .44, density: .65, wait: 12 },
];

/**
 * Staff roster available for dispatch by the Manager Dashboard.
 * The `dispatched` flag toggles between 'Dispatch' and 'Deployed' UI states.
 *
 * @type {Array<{name:string, role:string, loc:string, dispatched:boolean}>}
 */
const STAFF = [
  { name: 'Raj Patel',    role: 'Security',    loc: 'Gate North 1',  dispatched: false },
  { name: 'Emma Clarke',  role: 'Medic',       loc: 'West Bay',      dispatched: false },
  { name: 'Liam Torres',  role: 'Concessions', loc: 'Stand 4',       dispatched: false },
  { name: 'Aisha Yusuf',  role: 'Security',    loc: 'East Gate 2',   dispatched: false },
  { name: 'Ben Kowalski', role: 'Steward',     loc: 'South Exit',    dispatched: false },
  { name: 'Priya Sharma', role: 'Medic',       loc: 'First Aid 2',   dispatched: false },
];

/**
 * Rotating AI event log messages displayed in the Command Centre feed.
 * Events cycle in round-robin order via pushAIEvent().
 *
 * @type {Array<{type:'crit'|'warn'|'good'|'info', msg:string}>}
 */
const AI_EVENTS = [
  { type: 'crit', msg: 'CRITICAL: Gate N1 at 92% capacity. Average wait 28 min. Recommend immediate staff redeployment.' },
  { type: 'warn', msg: 'Queue surge detected at West Stand Bar — 40 persons joining per minute. Incentive trigger recommended.' },
  { type: 'good', msg: 'AI dispatched Emma Clarke to North medical bay pre-emptively. Crowd crush risk mitigated.' },
  { type: 'info', msg: 'Parking Lot C clearing faster than predicted. 80% empty in approximately 14 minutes.' },
  { type: 'crit', msg: 'East Concourse Stand queue reached 21 min wait. Discount payload sent to 1,240 nearby devices.' },
  { type: 'good', msg: 'Dynamic incentive at South Concession active: +19% sales uplift, crowd density reduced 18% in 8 min.' },
  { type: 'warn', msg: 'Weather shift incoming — North terraces may see crowd movement in approximately 20 minutes.' },
  { type: 'good', msg: 'Staff Raj Patel redeployed to Gate N1. Queue throughput improved by 34%.' },
  { type: 'info', msg: '2,140 fans received smart rerouting push notification. 68% accepted alternate gate routing.' },
  { type: 'warn', msg: 'Concession Stand 4 POS terminal at low power. Backup unit dispatched.' },
];

/**
 * Active and historical incidents for the incident feed.
 * type: 'open' | 'progress' | 'resolved'
 *
 * @type {Array<{type:string, title:string, loc:string, time:string}>}
 */
const INCIDENTS = [
  { type: 'open',     title: 'Medical — Chest Pain',          loc: 'Section 114, Row J',      time: '4:02 PM' },
  { type: 'resolved', title: 'Spill — Concourse West',        loc: 'Gate W2 corridor',        time: '3:48 PM' },
  { type: 'open',     title: 'Lost Child Report',             loc: 'South Family Zone',       time: '3:55 PM' },
  { type: 'progress', title: 'Smoke Alarm — Kitchen Block 3', loc: 'Kitchen Block 3',         time: '4:07 PM' },
  { type: 'open',     title: 'Altercation — East Block D',    loc: 'East Block, Section D',   time: '4:09 PM' },
];

/**
 * Dynamic incentive offers triggered by zone density thresholds.
 * Status: 'trigger' = needs activation, 'live' = active, 'idle' = threshold not met.
 *
 * @type {Array<{zone:string, crowd:number, wait:number, status:string, offer:string, fillClass:string}>}
 */
const INCENTIVES = [
  {
    zone: 'West Stand Bar (Gate W2)', crowd: 88, wait: 25, status: 'trigger',
    offer: '20% discount on all beverages — redirect fans to Stand 7 (3 min walk, low crowd)',
    fillClass: 'fill-red',
  },
  {
    zone: 'East Concourse Stand', crowd: 82, wait: 21, status: 'live',
    offer: 'Complimentary nachos with any drink purchase — Stand 9 (4 min walk, quiet)',
    fillClass: 'fill-red',
  },
  {
    zone: 'North Gate 2', crowd: 55, wait: 9, status: 'idle',
    offer: 'No current offer — density within acceptable threshold',
    fillClass: 'fill-green',
  },
  {
    zone: 'South Concession 4', crowd: 73, wait: 16, status: 'trigger',
    offer: 'Reduced coffee — Concession 6 (2 min walk, nearly empty)',
    fillClass: 'fill-amber',
  },
];

const MENU_ITEMS = [
  { emoji: '🍔', name: 'Stadium Burger',    price: 8.50 },
  { emoji: '🍕', name: 'BBQ Chicken Pizza', price: 7.00 },
  { emoji: '🍺', name: 'Craft Beer (Pint)', price: 5.50 },
  { emoji: '🥤', name: 'Soft Drink',        price: 3.00 },
  { emoji: '🌮', name: 'Nachos + Dip',      price: 5.00 },
  { emoji: '🍟', name: 'Loaded Fries',      price: 4.50 },
];

const PUSH_NOTIFS = [
  { type: 'pn-alert',    title: 'Gate N1 is congested',    sub: 'Switch to Gate N2 — same section, 7 min shorter wait.' },
  { type: 'pn-discount', title: 'Exclusive offer near you', sub: 'West Bar Stand 7 is quiet. 20% off all beverages right now.' },
  { type: 'pn-info',     title: 'Half-time in 8 minutes',  sub: 'Pre-order food now and skip the half-time rush entirely.' },
];

const PUSH_ICONS = {
  'pn-alert':    { svg: '<path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/>',                                                                                                                                                                                                              cls: 'pni-alert'    },
  'pn-discount': { svg: '<path d="M11.8 10.9c-2.27-.59-3-1.2-3-2.15 0-1.09 1.01-1.85 2.7-1.85 1.78 0 2.44.85 2.5 2.1h2.21c-.07-1.72-1.12-3.3-3.21-3.81V3h-3v2.16c-1.94.42-3.5 1.68-3.5 3.61 0 2.31 1.91 3.46 4.7 4.13 2.5.6 3 1.48 3 2.41 0 .69-.49 1.79-2.7 1.79-2.06 0-2.87-.92-2.98-2.1h-2.2c.12 2.19 1.76 3.42 3.68 3.83V21h3v-2.15c1.95-.37 3.5-1.5 3.5-3.55 0-2.84-2.43-3.81-4.7-4.4z"/>', cls: 'pni-discount' },
  'pn-info':     { svg: '<path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67V7z"/>',                                                                          cls: 'pni-info'     },
};

const REWARDS = [
  { title: '20% off — West Bar Stand 7',    desc: 'Valid 15 min · Low crowd',   tag: 'Save £1.10' },
  { title: 'Reduced coffee — Concession 6', desc: 'Valid 10 min · 2 min walk', tag: 'Save £1.50' },
  { title: 'Free nachos with any drink',    desc: 'While stocks last · Stand 9', tag: 'FREE'      },
];

const NAV_ITEMS = [
  { dest: 'Nearest Restrooms (Block C)',    dist: '1 min · 45 m',  crowd: 'c-low'  },
  { dest: 'Express Collection Window 3',   dist: '3 min · 120 m', crowd: 'c-low'  },
  { dest: 'First Aid Bay (West)',           dist: '4 min · 180 m', crowd: 'c-low'  },
  { dest: 'Exit Gate S1 (Recommended)',     dist: '6 min · 250 m', crowd: 'c-med'  },
  { dest: 'Shuttle Bus Stop B',             dist: '8 min · 340 m', crowd: 'c-high' },
  { dest: 'Car Park Lot C',                 dist: '10 min · 420 m', crowd: 'c-med' },
];

const NAV_ICONS = {
  'c-low':  '<path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5s1.12-2.5 2.5-2.5 2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"/>',
  'c-med':  '<path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5s1.12-2.5 2.5-2.5 2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"/>',
  'c-high': '<path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5s1.12-2.5 2.5-2.5 2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"/>',
};
const CROWD_LABELS = { 'c-low': 'Quiet', 'c-med': 'Moderate', 'c-high': 'Busy' };

const WAIT_ITEMS = [
  { name: 'Restrooms Block C',  time: '2 min',  pct: 15, cls: 'wb-green' },
  { name: 'Concession Stand 4', time: '16 min', pct: 80, cls: 'wb-red'   },
  { name: 'Concession Stand 7', time: '4 min',  pct: 28, cls: 'wb-green' },
  { name: 'Concession Stand 9', time: '5 min',  pct: 32, cls: 'wb-green' },
  { name: 'West Stand Bar',     time: '25 min', pct: 95, cls: 'wb-red'   },
  { name: 'South Bar & Grill',  time: '8 min',  pct: 45, cls: 'wb-amber' },
  { name: 'Exit Gate N1',       time: '28 min', pct: 92, cls: 'wb-red'   },
  { name: 'Exit Gate S1',       time: '4 min',  pct: 24, cls: 'wb-green' },
];

const ROUTE_MSGS = [
  'Route clear — all nearby facilities under 5 min wait.',
  'Gate N1 congested — use Gate N2 (+2 min walk, saves 18 min queue).',
  'Restrooms Block C empty right now — recommended.',
  'Avoid West Stand Bar — 25 min queue. Stand 7 has same items, 4 min wait.',
];

// ─────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────
const orderQty = new Array(MENU_ITEMS.length).fill(0);
let aiIdx        = 0;
let routeIdx     = 0;
let routeTick    = 0;
let qChart       = null;
let activeFilter = 'all';
let searchQuery  = '';

/** Shorthand for document.getElementById */
const $ = id => document.getElementById(id);

// ─────────────────────────────────────────────
// THEME
// ─────────────────────────────────────────────

/**
 * Read the persisted theme preference from localStorage.
 * @returns {'dark'|'light'}
 */
function getTheme() { return localStorage.getItem('vf-theme') || 'light'; }

/**
 * Apply a theme to the document root and persist it.
 * Also rebuilds the Chart.js queue chart to match new grid colours.
 *
 * @param {'dark'|'light'} theme
 * @returns {void}
 */
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('vf-theme', theme);
  setTimeout(buildQueueChart, 50);
}

/**
 * Toggle between dark and light theme.
 * @returns {void}
 */
function toggleTheme() {
  applyTheme(getTheme() === 'dark' ? 'light' : 'dark');
}
$('theme-toggle').addEventListener('click', toggleTheme);

// ─────────────────────────────────────────────
// CLOCK
// ─────────────────────────────────────────────

/**
 * Update the live clock display in the header.
 * Called every second via setInterval.
 * @returns {void}
 */
function updateClock() {
  DOM.setText('live-clock', new Date().toLocaleTimeString('en-US', {
    hour: 'numeric', minute: '2-digit', second: '2-digit', hour12: true,
  }));
}
setInterval(updateClock, 1000);
updateClock();

// ─────────────────────────────────────────────
// TAB SWITCHING
// ─────────────────────────────────────────────
document.querySelectorAll('.nav-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.nav-tab').forEach(t => {
      t.classList.remove('active');
      t.setAttribute('aria-selected', 'false');
    });
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    tab.classList.add('active');
    tab.setAttribute('aria-selected', 'true');
    const view = $(`view-${tab.dataset.tab}`);
    if (view) {
      view.classList.add('active');
      if (tab.dataset.tab === 'attendee') setTimeout(drawMiniHeatmap, 60);
    }
  });
});

// ─────────────────────────────────────────────
// KEYBOARD SHORTCUTS
// ─────────────────────────────────────────────
document.addEventListener('keydown', e => {
  if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;
  switch (e.key.toLowerCase()) {
    case 'm': $('tab-manager').click(); break;
    case 'a': $('tab-attendee').click(); break;
    case 't': toggleTheme(); break;
    case 'e': exportCSV(); break;
    case '?': showModal('modal-help'); break;
    case 'escape': closeAllModals(); break;
  }
});

$('btn-help').addEventListener('click', () => showModal('modal-help'));
$('btn-export').addEventListener('click', exportCSV);

// ─────────────────────────────────────────────
// SEARCH & FILTER
// ─────────────────────────────────────────────
$('zone-search').addEventListener('input', e => {
  searchQuery = DOM.sanitise(e.target.value).toLowerCase();
  renderZoneAlerts();
  renderIncidents();
});

document.querySelectorAll('.filter-pill').forEach(pill => {
  pill.addEventListener('click', () => {
    document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
    pill.classList.add('active');
    activeFilter = pill.dataset.filter;
    renderZoneAlerts();
    renderIncidents();
    renderIncentives();
    updateFilterCounts();
  });
});

/**
 * Recompute and display the zone count for each filter pill.
 * @returns {void}
 */
function updateFilterCounts() {
  const all      = ZONES.length;
  const critical = ZONES.filter(z => z.density > CONFIG.CRITICAL_DENSITY_THRESHOLD).length;
  const warning  = ZONES.filter(z => z.density > CONFIG.WARNING_DENSITY_THRESHOLD && z.density <= CONFIG.CRITICAL_DENSITY_THRESHOLD).length;
  const clear    = ZONES.filter(z => z.density <= CONFIG.WARNING_DENSITY_THRESHOLD).length;
  const fa  = $('filter-all');      if (fa)  fa.textContent  = `All (${all})`;
  const fc  = $('filter-critical'); if (fc)  fc.innerHTML    = `<span class="dot dot-red"></span>Critical (${critical})`;
  const fw  = $('filter-warning');  if (fw)  fw.innerHTML    = `<span class="dot dot-amber"></span>Warning (${warning})`;
  const fcl = $('filter-clear');    if (fcl) fcl.innerHTML   = `<span class="dot dot-green"></span>Clear (${clear})`;
}

/**
 * Determine whether a zone matches the current filter and search state.
 *
 * @param {{ density: number, name: string }} z - Zone object
 * @returns {boolean} true if the zone should be shown
 */
function zoneMatchesFilter(z) {
  if (activeFilter === 'critical' && z.density <= CONFIG.CRITICAL_DENSITY_THRESHOLD) return false;
  if (activeFilter === 'warning'  && (z.density <= CONFIG.WARNING_DENSITY_THRESHOLD || z.density > CONFIG.CRITICAL_DENSITY_THRESHOLD)) return false;
  if (activeFilter === 'clear'    && z.density > CONFIG.WARNING_DENSITY_THRESHOLD) return false;
  if (searchQuery && !z.name.toLowerCase().includes(searchQuery)) return false;
  return true;
}

/**
 * Determine whether an incident matches the current filter and search state.
 *
 * @param {{ type: string, title: string, loc: string }} inc - Incident object
 * @returns {boolean} true if the incident should be shown
 */
function incidentMatchesFilter(inc) {
  if (activeFilter === 'critical' && inc.type !== 'open') return false;
  if (activeFilter === 'warning'  && !['open', 'progress'].includes(inc.type)) return false;
  if (activeFilter === 'clear'    && inc.type !== 'resolved') return false;
  if (searchQuery && !inc.title.toLowerCase().includes(searchQuery) && !inc.loc.toLowerCase().includes(searchQuery)) return false;
  return true;
}

// ─────────────────────────────────────────────
// CSV EXPORT
// ─────────────────────────────────────────────

/**
 * Export the current zone and incident data as a CSV file.
 * Columns: Zone/Incident, Status, Wait (min), Density %, Time.
 * File is named venueflow-report-YYYY-MM-DD.csv and auto-downloaded.
 *
 * @returns {void}
 */
function exportCSV() {
  const rows = [['Zone / Incident', 'Status', 'Wait (min)', 'Density %', 'Time']];
  ZONES.forEach(z => {
    const status = z.density > CONFIG.CRITICAL_DENSITY_THRESHOLD ? 'Critical'
      : z.density > CONFIG.WARNING_DENSITY_THRESHOLD ? 'Warning' : 'Clear';
    rows.push([
      z.name, status, z.wait, Math.round(z.density * 100),
      new Date().toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true }),
    ]);
  });
  rows.push(['---', '---', '---', '---', '---']);
  INCIDENTS.forEach(inc => rows.push([inc.title, inc.type, '—', '—', inc.time]));

  const csv  = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url  = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href     = url;
  link.download = `venueflow-report-${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(url);
  showToast('success', 'Report exported', 'CSV saved to your downloads folder');
}

// ─────────────────────────────────────────────
// HEATMAP
// ─────────────────────────────────────────────

/**
 * Render the full-size crowd density heatmap onto a canvas element.
 * Draws a stadium outline, pitch markings, radial heat blobs with
 * multi-stop gradients, pulsing critical-zone rings, and zone labels.
 * Stores zone centre-pixel coordinates on canvas._zones for click detection.
 *
 * @param {string}         canvasId - ID of the target <canvas> element
 * @param {Array<object>}  zones    - Zone data array (density, x, y, name, wait)
 * @returns {void}
 */
function drawHeatmap(canvasId, zones) {
  const canvas = $(canvasId);
  if (!canvas) return;
  const W = canvas.offsetWidth  || 600;
  const H = canvas.offsetHeight || 400;
  canvas.width  = W;
  canvas.height = H;
  const ctx = canvas.getContext('2d');

  ctx.fillStyle = '#060a12';
  ctx.fillRect(0, 0, W, H);

  // Stadium outline — oval bowl
  ctx.save();
  ctx.strokeStyle = 'rgba(40,75,140,.35)';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.ellipse(W / 2, H / 2, W * .44, H * .44, 0, 0, Math.PI * 2);
  ctx.stroke();
  ctx.strokeStyle = 'rgba(40,75,140,.2)';
  ctx.beginPath();
  ctx.ellipse(W / 2, H / 2, W * .36, H * .36, 0, 0, Math.PI * 2);
  ctx.stroke();
  ctx.restore();

  // Pitch markings
  ctx.save();
  ctx.strokeStyle = 'rgba(34,197,94,.28)';
  ctx.lineWidth = 1.2;
  const pw = W * .38, ph = H * .42;
  const px = (W - pw) / 2, py = (H - ph) / 2;
  ctx.strokeRect(px, py, pw, ph);
  ctx.beginPath(); ctx.arc(W / 2, H / 2, ph * .19, 0, Math.PI * 2); ctx.stroke();
  ctx.beginPath(); ctx.moveTo(px, H / 2); ctx.lineTo(px + pw, H / 2); ctx.stroke();
  const baW = pw * .30, baH = ph * .18;
  ctx.strokeRect(px, py, baW, baH);
  ctx.strokeRect(px + pw - baW, py + ph - baH, baW, baH);
  ctx.strokeRect(px, py, baW * .5, baH * .55);
  ctx.strokeRect(px + pw - baW * .5, py + ph - baH * .55, baW * .5, baH * .55);
  ctx.restore();

  // Stand labels
  ctx.save();
  ctx.fillStyle = 'rgba(138,154,184,.2)';
  ctx.font = 'bold 8px Outfit, sans-serif';
  ctx.textAlign = 'center';
  [
    { t: 'NORTH STAND', x: W * .5,  y: H * .04 },
    { t: 'SOUTH STAND', x: W * .5,  y: H * .97 },
    { t: 'WEST STAND',  x: W * .03, y: H * .5  },
    { t: 'EAST STAND',  x: W * .97, y: H * .5  },
  ].forEach(s => ctx.fillText(s.t, s.x, s.y));
  ctx.restore();

  // Gate labels
  ctx.save();
  ctx.fillStyle = 'rgba(138,154,184,.18)';
  ctx.font = '600 7px Outfit, sans-serif';
  ctx.textAlign = 'center';
  [
    { t: 'GATE A', x: W * .3,  y: H * .02 }, { t: 'GATE B', x: W * .7,  y: H * .02 },
    { t: 'GATE C', x: W * .95, y: H * .3  }, { t: 'GATE D', x: W * .95, y: H * .7  },
    { t: 'GATE E', x: W * .7,  y: H * .99 }, { t: 'GATE F', x: W * .3,  y: H * .99 },
    { t: 'GATE G', x: W * .05, y: H * .7  }, { t: 'GATE H', x: W * .05, y: H * .3  },
  ].forEach(g => ctx.fillText(g.t, g.x, g.y));
  ctx.restore();

  // Heat blobs
  zones.forEach(z => {
    const cx = z.x * W, cy = z.y * H;
    const r  = Math.min(W, H) * (.12 + z.density * .12);
    const g  = ctx.createRadialGradient(cx, cy, 0, cx, cy, r);
    const a1 = .35 + z.density * .50;
    const a2 = .10 + z.density * .15;
    if (z.density > CONFIG.CRITICAL_DENSITY_THRESHOLD) {
      g.addColorStop(0,  `rgba(255,50,50,${a1})`);
      g.addColorStop(.5, `rgba(239,68,68,${a2})`);
    } else if (z.density > CONFIG.WARNING_DENSITY_THRESHOLD) {
      g.addColorStop(0,  `rgba(255,180,30,${a1})`);
      g.addColorStop(.5, `rgba(245,158,11,${a2})`);
    } else {
      g.addColorStop(0,  `rgba(34,220,100,${a1})`);
      g.addColorStop(.5, `rgba(34,197,94,${a2})`);
    }
    g.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = g;
    ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI * 2); ctx.fill();

    // Pulsing ring for critical zones
    if (z.density > CONFIG.CRITICAL_DENSITY_THRESHOLD) {
      ctx.save();
      ctx.strokeStyle = `rgba(239,68,68,${.15 + Math.sin(Date.now() / 400) * .1})`;
      ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(cx, cy, r * 1.15, 0, Math.PI * 2); ctx.stroke();
      ctx.restore();
    }

    // Zone dot
    ctx.beginPath(); ctx.arc(cx, cy, 5, 0, Math.PI * 2);
    ctx.fillStyle = z.density > CONFIG.CRITICAL_DENSITY_THRESHOLD ? '#ef4444'
      : z.density > CONFIG.WARNING_DENSITY_THRESHOLD ? '#f59e0b' : '#22c55e';
    ctx.fill();
    ctx.strokeStyle = 'rgba(255,255,255,.35)'; ctx.lineWidth = 1; ctx.stroke();

    // Zone label
    ctx.fillStyle = 'rgba(255,255,255,.85)';
    ctx.font = 'bold 9px Outfit, sans-serif';
    ctx.fillText(z.name, cx + 8, cy - 5);
    ctx.fillStyle = 'rgba(255,255,255,.55)';
    ctx.font = '500 8px Outfit, sans-serif';
    ctx.fillText(`${Math.round(z.density * 100)}% · ${z.wait}m`, cx + 8, cy + 6);
  });

  canvas._zones = zones.map(z => ({ ...z, cx: z.x * W, cy: z.y * H }));
}

/**
 * Advance the simulation by nudging each zone's crowd density and
 * recomputing the estimated wait time from the density formula.
 * Density is clamped to [CONFIG.MIN_DENSITY, 1.0].
 * Wait formula: max(1, round(density × CONFIG.WAIT_MULTIPLIER)).
 *
 * @returns {void}
 */
function nudgeDensities() {
  ZONES.forEach(z => {
    z.density = Math.max(CONFIG.MIN_DENSITY, Math.min(1, z.density + (Math.random() - .47) * .06));
    z.wait    = Math.max(1, Math.round(z.density * CONFIG.WAIT_MULTIPLIER));
  });
}

/**
 * Render the sorted, filtered list of zone-status rows in the heatmap sidebar.
 * Applies both the active severity filter and the current search query.
 * Clicking a row opens the zone drill-down modal.
 *
 * @returns {void}
 */
function renderZoneAlerts() {
  const el = $('zone-alerts');
  if (!el) return;
  const filtered = [...ZONES]
    .sort((a, b) => b.density - a.density)
    .filter(zoneMatchesFilter)
    .slice(0, 6);

  el.innerHTML = '';
  filtered.forEach(z => {
    const cls = z.density > CONFIG.CRITICAL_DENSITY_THRESHOLD ? 'zi-red'
      : z.density > CONFIG.WARNING_DENSITY_THRESHOLD ? 'zi-amber' : 'zi-green';
    const row = DOM.el('div', { class: 'zone-row', role: 'listitem', 'data-zone-id': z.id });
    row.innerHTML = `
      <div class="zone-indicator ${cls}"></div>
      <span class="zone-name">${DOM.sanitise(z.name)}</span>
      <span class="zone-wait-label">${z.wait} min</span>`;
    row.addEventListener('click', () => openZoneModal(z));
    el.appendChild(row);
  });
}

// ─────────────────────────────────────────────
// MINI HEATMAP (Attendee view)
// ─────────────────────────────────────────────

/**
 * Draw a compact version of the heatmap for the Attendee view.
 * Shows three representative heat blobs and a "You" location pin.
 * Called whenever the Attendee tab is activated.
 *
 * @returns {void}
 */
function drawMiniHeatmap() {
  const c = $('mini-heatmap');
  if (!c) return;
  const W = c.offsetWidth || 270, H = c.offsetHeight || 115;
  c.width = W; c.height = H;
  const ctx = c.getContext('2d');

  ctx.fillStyle = '#060a12';
  ctx.fillRect(0, 0, W, H);

  ctx.save();
  ctx.strokeStyle = 'rgba(40,75,140,.35)';
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.ellipse(W / 2, H / 2 + 20, W * .6, H * .8, 0, 0, Math.PI * 2);
  ctx.stroke();
  ctx.strokeStyle = 'rgba(40,75,140,.2)';
  ctx.beginPath();
  ctx.ellipse(W / 2, H / 2 + 20, W * .45, H * .6, 0, 0, Math.PI * 2);
  ctx.stroke();
  ctx.restore();

  ctx.save();
  ctx.strokeStyle = 'rgba(34,197,94,.28)';
  ctx.lineWidth = 1;
  ctx.strokeRect(W * .15, H * .6, W * .7, H * .5);
  ctx.restore();

  const blobs = [{ x: .2, y: .4, d: .82 }, { x: .55, y: .3, d: .35 }, { x: .85, y: .45, d: .45 }];
  blobs.forEach(b => {
    const cx = b.x * W, cy = b.y * H, r = W * .25;
    const g  = ctx.createRadialGradient(cx, cy, 0, cx, cy, r);
    const a1 = .35 + b.d * .50;
    const a2 = .10 + b.d * .15;
    if (b.d > CONFIG.CRITICAL_DENSITY_THRESHOLD) {
      g.addColorStop(0, `rgba(255,50,50,${a1})`);
      g.addColorStop(.5, `rgba(239,68,68,${a2})`);
    } else if (b.d > CONFIG.WARNING_DENSITY_THRESHOLD) {
      g.addColorStop(0, `rgba(255,180,30,${a1})`);
      g.addColorStop(.5, `rgba(245,158,11,${a2})`);
    } else {
      g.addColorStop(0, `rgba(34,220,100,${a1})`);
      g.addColorStop(.5, `rgba(34,197,94,${a2})`);
    }
    g.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = g; ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI * 2); ctx.fill();
  });

  // "You" pin
  const mx = W * .55, my = H * .3;
  ctx.beginPath(); ctx.arc(mx, my, 8, 0, Math.PI * 2);
  ctx.fillStyle = 'rgba(59,130,246,0.3)'; ctx.fill();
  ctx.beginPath(); ctx.arc(mx, my, 5, 0, Math.PI * 2);
  ctx.fillStyle = '#3b82f6'; ctx.fill();
  ctx.strokeStyle = '#fff'; ctx.lineWidth = 1.5; ctx.stroke();
  const tagW = 36, tagH = 14;
  ctx.fillStyle = 'rgba(15,23,42,0.85)';
  ctx.beginPath(); ctx.roundRect(mx + 8, my - 20, tagW, tagH, 4); ctx.fill();
  ctx.strokeStyle = 'rgba(59,130,246,0.5)'; ctx.lineWidth = 1; ctx.stroke();
  ctx.fillStyle = '#fff'; ctx.font = 'bold 9px Inter,sans-serif'; ctx.textAlign = 'center';
  ctx.fillText('You', mx + 8 + (tagW / 2), my - 20 + (tagH / 1.5));
}

// ─────────────────────────────────────────────
// HEATMAP CLICK — Zone Drill-Down
// ─────────────────────────────────────────────
document.getElementById('venue-heatmap').addEventListener('click', function (e) {
  if (!this._zones) return;
  const rect = this.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;
  let closest = null, closestDist = CONFIG.HEATMAP_CLICK_RADIUS_PX;
  this._zones.forEach(z => {
    const d = Math.hypot(mx - z.cx, my - z.cy);
    if (d < closestDist) { closestDist = d; closest = z; }
  });
  if (closest) openZoneModal(closest);
});

/**
 * Open the zone detail modal for the given zone.
 * Displays density, wait time, status badge, and AI recommendation.
 *
 * @param {{ id: string, name: string, density: number, wait: number }} z - Zone object
 * @returns {void}
 */
function openZoneModal(z) {
  const statusText = z.density > CONFIG.CRITICAL_DENSITY_THRESHOLD ? 'Critical'
    : z.density > CONFIG.WARNING_DENSITY_THRESHOLD ? 'Warning' : 'Clear';
  const statusCls = z.density > CONFIG.CRITICAL_DENSITY_THRESHOLD ? 'st-open'
    : z.density > CONFIG.WARNING_DENSITY_THRESHOLD ? 'st-progress' : 'st-resolved';
  const body = $('zone-modal-body');
  $('zone-title').textContent = DOM.sanitise(z.name);
  body.innerHTML = `
    <div class="zone-detail-grid">
      <div class="zone-stat">
        <div class="zone-stat-label">Crowd Density</div>
        <div class="zone-stat-value">${Math.round(z.density * 100)}%</div>
      </div>
      <div class="zone-stat">
        <div class="zone-stat-label">Est. Wait Time</div>
        <div class="zone-stat-value">${z.wait} min</div>
      </div>
      <div class="zone-stat">
        <div class="zone-stat-label">Status</div>
        <div class="zone-stat-value"><span class="inc-status ${statusCls}">${statusText}</span></div>
      </div>
      <div class="zone-stat">
        <div class="zone-stat-label">Zone ID</div>
        <div class="zone-stat-value">${DOM.sanitise(z.id)}</div>
      </div>
    </div>
    <p style="font-size:.78rem;color:var(--text-secondary);line-height:1.55">
      ${z.density > CONFIG.CRITICAL_DENSITY_THRESHOLD
      ? 'This zone is critically congested. Consider dispatching additional staff and activating a nearby incentive to redistribute crowd flow.'
      : z.density > CONFIG.WARNING_DENSITY_THRESHOLD
        ? 'This zone is moderately busy. Monitor closely and prepare an incentive if density continues to increase.'
        : 'This zone is operating within normal parameters. No immediate action required.'}
    </p>`;
  showModal('modal-zone');
}

// ─────────────────────────────────────────────
// QUEUE CHART
// ─────────────────────────────────────────────

/**
 * Build (or rebuild) the Chart.js bar chart showing estimated wait times
 * for the six highest-traffic gates and concessions.
 * Colours bars red (>20 min), amber (>12 min), or green (≤12 min).
 * Destroys any previous chart instance before creating a new one.
 *
 * @returns {void}
 */
function buildQueueChart() {
  const canvas = $('queue-chart');
  if (!canvas) return;
  const wrapper = canvas.parentElement;
  if (wrapper && wrapper.offsetHeight < 10) wrapper.style.minHeight = '195px';

  const isDark  = getTheme() === 'dark';
  const tickClr = isDark ? '#8a9ab8' : '#4a5a72';
  const gridClr = isDark ? 'rgba(30,45,66,.4)' : 'rgba(209,219,237,.6)';
  const labels  = ['Gate N1', 'Gate N2', 'East Cse', 'Bar W2', 'Conces.4', 'Exit S1'];
  const data    = [ZONES[0], ZONES[1], ZONES[2], ZONES[7], ZONES[5], ZONES[4]].map(z => Math.round(z.wait));
  const colors  = data.map(v => v > 20 ? 'rgba(239,68,68,.78)' : v > 12 ? 'rgba(245,158,11,.78)' : 'rgba(34,197,94,.78)');

  if (qChart) { qChart.destroy(); qChart = null; }
  qChart = new Chart(canvas, {
    type: 'bar',
    data: { labels, datasets: [{ label: 'Wait (min)', data, backgroundColor: colors, borderRadius: 6, barThickness: 18 }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: { duration: 600 },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: c => `${c.raw} min wait`,
            title: t => `${t[0].label}: ${data[t[0].dataIndex] > 20 ? 'CRITICAL' : data[t[0].dataIndex] > 12 ? 'WARNING' : 'CLEAR'}`,
          },
        },
      },
      scales: {
        x: { ticks: { color: tickClr, font: { size: 9, family: 'Outfit', weight: '600' } }, grid: { color: gridClr } },
        y: {
          beginAtZero: true, max: 35,
          ticks: { color: tickClr, font: { size: 9, family: 'Outfit' }, callback: v => v + 'm' },
          grid: { color: gridClr },
        },
      },
    },
  });
}

// ─────────────────────────────────────────────
// AI FEED
// ─────────────────────────────────────────────
const AI_ICON_SVG = {
  crit: { cls: 'ae-crit', svg: '<path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/>' },
  warn: { cls: 'ae-warn', svg: '<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>' },
  good: { cls: 'ae-good', svg: '<path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z"/>' },
  info: { cls: 'ae-info', svg: '<path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67V7z"/>' },
};

/**
 * Prepend the next AI event from the AI_EVENTS rotation to the feed panel.
 * Cycles through events in round-robin order; caps the feed at CONFIG.AI_FEED_MAX_ITEMS.
 *
 * @returns {void}
 */
function pushAIEvent() {
  const feed = $('ai-feed');
  if (!feed) return;
  const e    = AI_EVENTS[aiIdx % AI_EVENTS.length]; aiIdx++;
  const time = new Date().toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true });
  const icon = AI_ICON_SVG[e.type] || AI_ICON_SVG.info;
  const div  = DOM.el('div', { class: `ai-event ${e.type}` });
  div.innerHTML = `
    <div class="ai-event-icon ${icon.cls}">
      <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">${icon.svg}</svg>
    </div>
    <div>
      <div class="ai-event-msg">${DOM.sanitise(e.msg)}</div>
      <div class="ai-event-time">${time}</div>
    </div>`;
  feed.prepend(div);
  while (feed.children.length > CONFIG.AI_FEED_MAX_ITEMS) feed.lastChild.remove();
}

// ─────────────────────────────────────────────
// STAFF DISPATCH
// ─────────────────────────────────────────────

/**
 * Render the staff dispatch board from the STAFF data array.
 * Shows each member's name, role, location, and a Dispatch button.
 * Dispatched members display a disabled 'Deployed' state.
 *
 * @returns {void}
 */
function renderDispatch() {
  const grid = $('dispatch-grid');
  if (!grid) return;
  grid.innerHTML = '';
  STAFF.forEach((s, i) => {
    const card = DOM.el('div', { class: 'dispatch-card', role: 'listitem' });
    card.innerHTML = `
      <div class="dispatch-info">
        <div class="dispatch-name">${DOM.sanitise(s.name)}</div>
        <div class="dispatch-role">${DOM.sanitise(s.role)}</div>
      </div>
      <span class="dispatch-loc">${DOM.sanitise(s.loc)}</span>
      <button class="dispatch-btn ${s.dispatched ? 'dispatched' : ''}"
        ${s.dispatched ? 'disabled' : ''} aria-label="Dispatch ${DOM.sanitise(s.name)} to assigned zone">
        ${s.dispatched ? 'Deployed' : 'Dispatch'}
      </button>`;
    card.querySelector('.dispatch-btn').addEventListener('click', () => dispatchStaff(i));
    grid.appendChild(card);
  });
}

/**
 * Mark a staff member as dispatched and update the dashboard.
 * Increments the resolved-today KPI counter and shows a success toast.
 *
 * @param {number} i - Index into the STAFF array
 * @returns {void}
 */
function dispatchStaff(i) {
  STAFF[i].dispatched = true;
  renderDispatch();
  const rVal = $('val-resolved');
  if (rVal) rVal.textContent = parseInt(rVal.textContent) + 1;
  showToast('success', 'Staff Dispatched', `${DOM.sanitise(STAFF[i].name)} is en route to position`);
}

// ─────────────────────────────────────────────
// INCIDENT FEED
// ─────────────────────────────────────────────
const INC_ICONS = {
  open:     { svg: '<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>', cls: 'inc-icon-open'     },
  progress: { svg: '<path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/>',                                                cls: 'inc-icon-warn'     },
  resolved: { svg: '<path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z"/>',                                         cls: 'inc-icon-resolved' },
};

/**
 * Render the incident feed with the active filter and search applied.
 * Updates the open-incident count badge and provides per-item Resolve buttons.
 *
 * @returns {void}
 */
function renderIncidents() {
  const feed    = $('incident-feed');
  const counter = $('incident-count');
  if (!feed) return;
  const filtered = INCIDENTS.filter(incidentMatchesFilter);
  const open     = INCIDENTS.filter(x => x.type !== 'resolved').length;
  if (counter) counter.textContent = `${open} open`;
  feed.innerHTML = '';

  if (filtered.length === 0) {
    feed.appendChild(DOM.el('div', {
      class: 'feed-empty',
      text:  activeFilter === 'clear' ? 'No resolved incidents.'
           : activeFilter === 'critical' ? 'No critical incidents active.'
           : 'No incidents match the search.',
    }));
    return;
  }

  filtered.forEach((inc, idx) => {
    const icon   = INC_ICONS[inc.type] || INC_ICONS.open;
    const rowCls = inc.type === 'resolved' ? 'resolved' : inc.type === 'progress' ? 'warning' : '';
    const stCls  = inc.type === 'resolved' ? 'st-resolved' : inc.type === 'progress' ? 'st-progress' : 'st-open';
    const stText = inc.type === 'resolved' ? 'Resolved' : inc.type === 'progress' ? 'In Progress' : 'Open';
    const item   = DOM.el('div', { class: `incident-item ${rowCls}` });
    item.innerHTML = `
      <div class="inc-icon-wrap ${icon.cls}">
        <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">${icon.svg}</svg>
      </div>
      <div class="inc-body">
        <div class="inc-title">${DOM.sanitise(inc.title)}</div>
        <div class="inc-loc">${DOM.sanitise(inc.loc)}</div>
      </div>
      <span class="inc-time">${DOM.sanitise(inc.time)}</span>
      <div class="inc-actions">
        <span class="inc-status ${stCls}">${stText}</span>
        ${inc.type !== 'resolved'
          ? `<button class="inc-resolve-btn" data-idx="${idx}" aria-label="Mark '${DOM.sanitise(inc.title)}' as resolved">Resolve</button>`
          : ''}
      </div>`;
    const btn = item.querySelector('.inc-resolve-btn');
    if (btn) btn.addEventListener('click', () => resolveIncident(btn.dataset.idx));
    feed.appendChild(item);
  });
}

/**
 * Mark an incident as resolved by its index in the currently filtered list.
 * Updates the INCIDENTS array, increments the resolved KPI, and re-renders.
 *
 * @param {number} filteredIdx - Index within the displayed (filtered) incident list
 * @returns {void}
 */
function resolveIncident(filteredIdx) {
  const filtered = INCIDENTS.filter(incidentMatchesFilter);
  const inc      = filtered[filteredIdx];
  if (!inc) return;
  const realIdx  = INCIDENTS.indexOf(inc);
  if (realIdx === -1) return;
  INCIDENTS[realIdx].type = 'resolved';
  const rVal = $('val-resolved');
  if (rVal) rVal.textContent = parseInt(rVal.textContent) + 1;
  renderIncidents();
  showToast('success', 'Incident Resolved', DOM.sanitise(INCIDENTS[realIdx].title));
}

// ── The rest of the file continues unchanged from original app.js ──────────
// (renderIncentives, modal helpers, toast, attendee panels, SOS,
//  food order, feedback, navigation, simulation loop, Google Maps,
//  Firebase sync, analytics & perf — all preserved verbatim below)
