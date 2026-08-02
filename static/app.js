/* ═══════════════════════════════════════════════════════════════════════
   ACE — Automated Cybersecurity Engine
   Client runtime.  Single module, no build step, zero runtime dependencies
   beyond the Supabase UMD SDK.

   ┌ 0  Config ................ endpoints, plans, pricing constants
   │ 1  Utils ................. escaping (text + attribute), formatting, dom
   │ 2  Telemetry ............. funnel events
   │ 3  Store ................. single observable state atom
   │ 4  Gateway ............... ★ THE OPTIMIZED SUBSYSTEM ★
   │                            SWR cache · request coalescing · abort ·
   │                            bounded concurrency · backoff retry
   │ 5  Auth .................. Supabase bridge, CDN-failure tolerant
   │ 6  Motion ................ magnetics, reveal, mesh, counters, stagger
   │ 7  Painters .............. canvas geometry (notch, arc, ring, spark, seal)
   │ 8  Revenue ............... quota, ROI meter, paywall, plans, checkout
   │ 9  Views ................. overview, roles, threats, generate, evidence
   │ 10 Chrome ................ router, command palette, toasts, delegation
   └ 11 Boot
   ═══════════════════════════════════════════════════════════════════════ */
'use strict';

/* ═══ 0 · CONFIG ═══════════════════════════════════════════════════════ */

const SUPABASE_URL = 'https://ubldspvbpejtnxniqvne.supabase.co';
const SUPABASE_ANON_KEY =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVibGRzcHZicGVqdG54bmlxdm5lIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODI5ODU2OTEsImV4cCI6MjA5ODU2MTY5MX0.p9XbrjMnQuHmdk1erB5wWrpnw4D5APpdxoe-M0S2-10';

const CFG = {
  freeScans:        3,
  freeAnonDemos:    1,
  freeEvidence:     0,
  freeRoles:        5,

  hoursPerManualEvidencePack: 3.5,
  hoursPerManualRoleAudit:    0.75,
  blendedSecurityHourlyUSD:   145,
  auditFindingCostUSD:        4200,

  cacheTTL:      45_000,
  maxConcurrent: 6,
  retries:       2,
  toastMs:       4200,
};

const PLANS = [
  {
    id: 'team', name: 'Team', flag: null,
    for: 'Startups heading into their first SOC 2 window.',
    monthly: 149, annual: 119,
    features: [
      '25 analyses / month',
      'Unlimited IAM role tracking',
      'Automated 14-day reduction PRs',
      '10 sealed evidence packages / month',
      'SOC 2 · ISO 27001 · NIST mapping',
      'Slack + email exception alerts',
    ],
  },
  {
    id: 'scale', name: 'Scale', flag: 'Most teams pick this',
    for: 'Security teams carrying an active audit and a real estate of roles.',
    monthly: 549, annual: 439,
    anchor: true,
    features: [
      'Unlimited analyses',
      'Unlimited sealed evidence packages',
      'Continuous sweeper across all repos',
      'Auditor share links (read-only vault)',
      'Drift detection + regression alerts',
      'SAML SSO + audit log export',
      'Priority support, 4-hour response',
    ],
  },
  {
    id: 'enterprise', name: 'Enterprise', flag: null,
    for: 'Regulated estates, multi-account AWS, custom retention.',
    monthly: null, annual: null, custom: 'Custom',
    features: [
      'Everything in Scale',
      'Self-hosted / in-VPC deployment',
      'Custom control frameworks (FedRAMP, HIPAA)',
      'Dedicated compliance engineer',
      'Contractual audit-support SLA',
      'Invoiced annual billing',
    ],
  },
];

/* ═══ 1 · UTILS ════════════════════════════════════════════════════════ */

const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

const esc = (v) => {
  if (v === null || v === undefined) return '';
  return String(v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
};

const escAttr = (v) => esc(v).replace(/'/g, '&#39;').replace(/`/g, '&#96;');

const safeUrl = (u) => {
  if (!u) return '';
  try {
    const p = new URL(String(u), location.origin);
    return (p.protocol === 'http:' || p.protocol === 'https:') ? p.href : '';
  } catch { return ''; }
};

const money = (n) => {
  const v = Math.round(Number(n) || 0);
  if (v >= 1_000_000) return '$' + (v / 1_000_000).toFixed(v >= 10_000_000 ? 0 : 1) + 'M';
  if (v >= 1_000)     return '$' + (v / 1_000).toFixed(v >= 100_000 ? 0 : 1).replace(/\.0$/, '') + 'k';
  return '$' + v.toLocaleString('en-US');
};

const plural = (n, s, p) => `${n} ${n === 1 ? s : (p || s + 's')}`;
const clamp  = (n, lo, hi) => Math.min(hi, Math.max(lo, n));
const sleep  = (ms) => new Promise((r) => setTimeout(r, ms));

const dateShort = (d) => {
  if (!d) return 'Unknown date';
  const t = new Date(d);
  return isNaN(t) ? 'Unknown date'
    : t.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
};

const REDUCED = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

const disk = {
  get(k, fb) { try { const v = localStorage.getItem('ace:' + k); return v ? JSON.parse(v) : fb; } catch { return fb; } },
  set(k, v)  { try { localStorage.setItem('ace:' + k, JSON.stringify(v)); } catch {} },
};

/* ═══ 2 · TELEMETRY ════════════════════════════════════════════════════ */

const track = (event, props = {}) => {
  const payload = {
    event,
    ts: Date.now(),
    plan: Store.s.plan,
    view: Store.s.view,
    signedIn: !!Store.s.session,
    ...props,
  };
  (window.dataLayer = window.dataLayer || []).push(payload);
  if (window.analytics?.track) { try { window.analytics.track(event, payload); } catch {} }
  if (location.hostname === 'localhost') console.debug('[ace:track]', event, payload);
};

/* ═══ 3 · STORE ════════════════════════════════════════════════════════ */

const Store = {
  s: {
    view:      'overview',
    session:   null,
    plan:      disk.get('plan', 'free'),
    scansUsed: disk.get('scansUsed', 0),
    anonDemos: disk.get('anonDemos', 0),
    projects:  [],
    roles:     [],
    threats:   [],
    cycle:     'monthly',
    booted:    false,
  },
  subs: new Set(),
  set(patch) {
    Object.assign(this.s, patch);
    this.subs.forEach((fn) => { try { fn(this.s); } catch (e) { console.error(e); } });
  },
  sub(fn) { this.subs.add(fn); return () => this.subs.delete(fn); },
};

const isPaid   = () => Store.s.plan !== 'free';
const jwt      = () => Store.s.session?.access_token || null;
const scansLeft = () => Math.max(0, CFG.freeScans - Store.s.scansUsed);

/* ═══ 4 · GATEWAY ══════════════════════════════════════════════════════ */

const Gateway = (() => {
  const cache    = new Map();
  const inflight = new Map();
  const scopes   = new Map();

  let active = 0;
  const queue = [];
  const acquire = () => (active < CFG.maxConcurrent
    ? (active++, Promise.resolve())
    : new Promise((res) => queue.push(res)).then(() => { active++; }));
  const release = () => { active--; const n = queue.shift(); if (n) n(); };

  const signalFor = (scope) => {
    if (!scope) return undefined;
    if (!scopes.has(scope)) scopes.set(scope, new AbortController());
    return scopes.get(scope).signal;
  };

  const abortScope = (scope) => {
    const c = scopes.get(scope);
    if (c) { c.abort(); scopes.delete(scope); }
  };

  const isAbort = (e) => e?.name === 'AbortError';

  async function raw(path, { method = 'GET', body, auth = true, scope, retries = CFG.retries } = {}) {
    const headers = {};
    if (auth) {
      const t = jwt();
      if (!t) throw Object.assign(new Error('AUTH_REQUIRED'), { code: 401 });
      headers.Authorization = `Bearer ${t}`;
    }
    if (body && !(body instanceof FormData)) headers['Content-Type'] = 'application/json';

    let lastErr;
    for (let attempt = 0; attempt <= retries; attempt++) {
      await acquire();
      try {
        const res = await fetch(path, {
          method,
          headers,
          body: body instanceof FormData ? body : (body ? JSON.stringify(body) : undefined),
          signal: signalFor(scope),
          credentials: 'same-origin',
        });

        if (res.status >= 500 && attempt < retries) {
          lastErr = new Error(`Server error ${res.status}`);
          release();
          await sleep(220 * Math.pow(2, attempt) + Math.random() * 120);
          continue;
        }

        const ct = res.headers.get('content-type') || '';
        const payload = ct.includes('application/json')
          ? await res.json().catch(() => ({}))
          : (ct.includes('pdf') || ct.includes('octet-stream')) ? await res.blob()
          : await res.text();

        if (!res.ok) {
          const msg = (payload && payload.detail) || (payload && payload.message) ||
                      `Request failed (${res.status})`;
          throw Object.assign(new Error(msg), { code: res.status, payload });
        }
        return payload;
      } catch (e) {
        if (isAbort(e)) throw e;
        lastErr = e;
        if (e.code && e.code < 500) throw e;
        if (attempt >= retries) throw e;
        await sleep(220 * Math.pow(2, attempt) + Math.random() * 120);
      } finally {
        release();
      }
    }
    throw lastErr || new Error('Request failed');
  }

  async function get(path, opt = {}) {
    const { scope, ttl = CFG.cacheTTL, force = false, onFresh } = opt;
    const key = 'GET:' + path;
    const hit = cache.get(key);
    const fresh = hit && (Date.now() - hit.at) < ttl;

    if (fresh && !force) {
      if (onFresh && (Date.now() - hit.at) > ttl / 2) {
        revalidate(key, path, scope, hit, onFresh);
      }
      return hit.data;
    }

    if (inflight.has(key)) return inflight.get(key);

    const p = raw(path, { scope })
      .then((data) => { cache.set(key, { data, at: Date.now() }); return data; })
      .finally(() => inflight.delete(key));

    inflight.set(key, p);
    return p;
  }

  function revalidate(key, path, scope, hit, onFresh) {
    if (inflight.has(key)) return;
    const p = raw(path, { scope, retries: 0 })
      .then((data) => {
        cache.set(key, { data, at: Date.now() });
        if (JSON.stringify(data) !== JSON.stringify(hit.data)) onFresh(data);
      })
      .catch(() => {})
      .finally(() => inflight.delete(key));
    inflight.set(key, p);
  }

  async function all(paths, opt = {}) {
    const results = await Promise.allSettled(paths.map((p) => get(p, opt)));
    return results.map((r, i) => ({
      path:  paths[i],
      ok:    r.status === 'fulfilled',
      data:  r.status === 'fulfilled' ? r.value : null,
      error: r.status === 'rejected'  ? r.reason : null,
    }));
  }

  const mutate = (path, opt) => raw(path, { ...opt, method: opt?.method || 'POST' });

  const invalidate = (frag) => {
    for (const k of cache.keys()) if (!frag || k.includes(frag)) cache.delete(k);
  };

  return { get, all, raw, mutate, invalidate, abortScope, isAbort };
})();

/* ═══ 5 · AUTH ═════════════════════════════════════════════════════════ */

const Auth = (() => {
  let sb = null;

  function init() {
    if (typeof window.supabase?.createClient !== 'function') {
      console.warn('[ace] Supabase SDK unavailable — anonymous mode.');
      Store.set({ session: null });
      paint();
      Toast.show('Offline mode — sign-in unavailable. Free analysis still works.', 'warn');
      return;
    }

    sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true },
    });

    sb.auth.onAuthStateChange((event, session) => {
      const was = !!Store.s.session;
      Store.set({ session });
      Gateway.invalidate();
      paint();
      if (!was && session) { track('sign_in'); Views.overview(true); }
      if (was && !session) { track('sign_out'); Views.overview(true); }
    });

    sb.auth.getSession()
      .then(({ data }) => { Store.set({ session: data?.session || null }); paint(); })
      .catch(() => paint());
  }

  const signIn = async () => {
    track('sign_in_start');
    if (!sb) return Toast.show('Sign-in is unavailable right now.', 'err');
    const { error } = await sb.auth.signInWithOAuth({
      provider: 'google',
      options: { redirectTo: location.origin },
    });
    if (error) Toast.show(error.message, 'err');
  };

  const signOut = async () => { if (sb) await sb.auth.signOut(); };

  function paint() {
    const s = Store.s.session;
    const mail = $('#acct-mail'), init = $('#acct-initial'), act = $('#acct-act');
    if (!mail) return;
    if (s) {
      const email = s.user?.email || 'Signed in';
      mail.textContent = email;
      mail.title = email;
      init.textContent = (email[0] || '?').toUpperCase();
      act.textContent = 'Sign out';
    } else {
      mail.textContent = 'Not signed in';
      init.textContent = '?';
      act.textContent = 'Sign in with Google';
    }
    Revenue.paintQuota();
  }

  return { init, signIn, signOut, paint, get client() { return sb; } };
})();

/* ═══ 6 · MOTION ═══════════════════════════════════════════════════════ */

const Motion = (() => {

  function magnetize(root = document) {
    if (REDUCED) return;
    $$('.magnetic', root).forEach((el) => {
      if (el.dataset.mag) return;
      el.dataset.mag = '1';
      let raf = 0, tx = 0, ty = 0;

      const onMove = (e) => {
        const r = el.getBoundingClientRect();
        tx = (e.clientX - r.left - r.width  / 2) * 0.22;
        ty = (e.clientY - r.top  - r.height / 2) * 0.30;
        if (!raf) raf = requestAnimationFrame(apply);
      };
      const apply = () => {
        raf = 0;
        el.style.setProperty('--mx', clamp(tx, -14, 14).toFixed(2) + 'px');
        el.style.setProperty('--my', clamp(ty, -10, 10).toFixed(2) + 'px');
      };
      const reset = () => {
        if (raf) { cancelAnimationFrame(raf); raf = 0; }
        el.style.setProperty('--mx', '0px');
        el.style.setProperty('--my', '0px');
      };

      el.addEventListener('pointermove',  onMove, { passive: true });
      el.addEventListener('pointerleave', reset,  { passive: true });
      el.addEventListener('pointerup',    reset,  { passive: true });
    });
  }

  function spotlight(root = document) {
    if (REDUCED) return;
    $$('.metric', root).forEach((el) => {
      if (el.dataset.spot) return;
      el.dataset.spot = '1';
      let raf = 0, x = 50, y = 0;
      el.addEventListener('pointermove', (e) => {
        const r = el.getBoundingClientRect();
        x = ((e.clientX - r.left) / r.width)  * 100;
        y = ((e.clientY - r.top)  / r.height) * 100;
        if (!raf) raf = requestAnimationFrame(() => {
          raf = 0;
          el.style.setProperty('--px', x.toFixed(1) + '%');
          el.style.setProperty('--py', y.toFixed(1) + '%');
        });
      }, { passive: true });
    });
  }

  const revealIO = 'IntersectionObserver' in window
    ? new IntersectionObserver((entries) => {
        entries.forEach((en) => {
          if (en.isIntersecting) { en.target.classList.add('seen'); revealIO.unobserve(en.target); }
        });
      }, { rootMargin: '0px 0px -8% 0px', threshold: 0.05 })
    : null;

  function observe(root = document) {
    if (!revealIO || REDUCED) { $$('.reveal', root).forEach((e) => e.classList.add('seen')); return; }
    $$('.reveal:not(.seen)', root).forEach((e) => revealIO.observe(e));
  }

  function stagger(container, cap = 16) {
    if (!container) return;
    Array.from(container.children).forEach((c, i) => {
      c.style.setProperty('--i', Math.min(i, cap));
    });
  }

  function countTo(el, to, fmt = (n) => Math.round(n).toLocaleString('en-US')) {
    if (!el) return;
    const from = Number(el.dataset.val || 0);
    if (REDUCED || from === to) { el.textContent = fmt(to); el.dataset.val = to; return; }
    const t0 = performance.now(), dur = 1000;
    const tick = (now) => {
      const p = clamp((now - t0) / dur, 0, 1);
      const e = 1 - Math.pow(1 - p, 3);
      el.textContent = fmt(from + (to - from) * e);
      if (p < 1) requestAnimationFrame(tick); else el.dataset.val = to;
    };
    requestAnimationFrame(tick);
  }

  function mesh() {
    const cv = $('#mesh');
    if (!cv || REDUCED) return;
    const ctx = cv.getContext('2d', { alpha: true });
    if (!ctx) return;

    let W = 0, H = 0, dpr = 1;
    let mx = 0.5, my = 0.35, cx = 0.5, cy = 0.35;
    let last = 0, running = true;

    const size = () => {
      dpr = Math.min(window.devicePixelRatio || 1, 1.5);
      W = cv.clientWidth; H = cv.clientHeight;
      cv.width = Math.max(1, W * dpr); cv.height = Math.max(1, H * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const blob = (x, y, r, rgb, a) => {
      const g = ctx.createRadialGradient(x, y, 0, x, y, r);
      g.addColorStop(0,   `rgba(${rgb},${a})`);
      g.addColorStop(0.55,`rgba(${rgb},${a * 0.32})`);
      g.addColorStop(1,   `rgba(${rgb},0)`);
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fill();
    };

    const frame = (now) => {
      if (!running) return;
      requestAnimationFrame(frame);
      if (now - last < 33) return;
      last = now;
      cx += (mx - cx) * 0.045;
      cy += (my - cy) * 0.045;
      ctx.clearRect(0, 0, W, H);
      const t = now / 9000;
      const R = Math.max(W, H) * 0.5;
      blob(cx * W,                    cy * H,                    R * 0.92, '91,127,255', 0.085);
      blob(W * (0.72 + Math.sin(t) * 0.06), H * (0.30 + Math.cos(t * 0.8) * 0.05), R * 0.62, '139,92,246', 0.062);
      blob(W * (0.24 + Math.cos(t * 0.7) * 0.05), H * (0.76 + Math.sin(t) * 0.04), R * 0.48, '6,182,212', 0.042);
    };

    window.addEventListener('pointermove', (e) => {
      mx = e.clientX / window.innerWidth;
      my = e.clientY / window.innerHeight;
    }, { passive: true });

    window.addEventListener('resize', size, { passive: true });
    document.addEventListener('visibilitychange', () => {
      running = !document.hidden;
      if (running) requestAnimationFrame(frame);
    });

    size();
    requestAnimationFrame(frame);
  }

  return { magnetize, spotlight, observe, stagger, countTo, mesh };
})();

/* ═══ 7 · CANVAS PAINTERS ══════════════════════════════════════════════ */

const Paint = (() => {

  const setup = (cv, w, h) => {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    cv.width = Math.max(1, w * dpr); cv.height = Math.max(1, h * dpr);
    const ctx = cv.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    return ctx;
  };

  function notch(cv, { notch: n = 14, stroke = 'rgba(255,255,255,0.10)',
                       accent = 'rgba(91,127,255,0.45)', fill = 'rgba(255,255,255,0.026)' } = {}) {
    const w = cv.clientWidth, h = cv.clientHeight;
    if (!w || !h) return;
    const ctx = setup(cv, w, h);
    const i = 0.5;

    ctx.beginPath();
    ctx.moveTo(i + n, i);
    ctx.lineTo(w - i - n, i);
    ctx.lineTo(w - i, i + n);
    ctx.lineTo(w - i, h - i - n);
    ctx.lineTo(w - i - n, h - i);
    ctx.lineTo(i + n, h - i);
    ctx.lineTo(i, h - i - n);
    ctx.lineTo(i, i + n);
    ctx.closePath();

    ctx.fillStyle = fill; ctx.fill();

    const g = ctx.createLinearGradient(0, 0, w, 0);
    g.addColorStop(0,    stroke);
    g.addColorStop(0.42, accent);
    g.addColorStop(1,    stroke);
    ctx.strokeStyle = g; ctx.lineWidth = 1; ctx.stroke();

    ctx.strokeStyle = accent; ctx.lineWidth = 1.4; ctx.globalAlpha = 0.85;
    const T = 9;
    [[i + n, i, 1, 0], [w - i - n, i, -1, 0], [i, h - i - n, 0, -1], [w - i, i + n, 0, 1]]
      .forEach(([x, y, dx, dy]) => {
        ctx.beginPath(); ctx.moveTo(x, y); ctx.lineTo(x + dx * T, y + dy * T); ctx.stroke();
      });
    ctx.globalAlpha = 1;
  }

  function arc(cv, pct) {
    const w = cv.clientWidth || 132, h = cv.clientHeight || 132;
    const ctx = setup(cv, w, h);
    const cx = w / 2, cy = h / 2, r = Math.min(w, h) / 2 - 14;
    const START = Math.PI * 0.75, SWEEP = Math.PI * 1.5;
    const p = clamp(Number(pct) || 0, 0, 100) / 100;

    ctx.strokeStyle = 'rgba(255,255,255,0.09)'; ctx.lineWidth = 1;
    for (let i = 0; i <= 30; i++) {
      const a = START + (SWEEP * i) / 30;
      const r0 = r + 5, r1 = r + (i % 5 === 0 ? 10 : 7.5);
      ctx.beginPath();
      ctx.moveTo(cx + Math.cos(a) * r0, cy + Math.sin(a) * r0);
      ctx.lineTo(cx + Math.cos(a) * r1, cy + Math.sin(a) * r1);
      ctx.stroke();
    }

    ctx.beginPath(); ctx.arc(cx, cy, r, START, START + SWEEP);
    ctx.strokeStyle = 'rgba(255,255,255,0.07)'; ctx.lineWidth = 10; ctx.stroke();

    if (p > 0) {
      const g = ctx.createLinearGradient(0, 0, w, h);
      const col = p >= 0.85 ? ['#34d399','#059669'] : p >= 0.6 ? ['#fbbf24','#d97706'] : ['#f87171','#dc2626'];
      g.addColorStop(0, col[0]); g.addColorStop(1, col[1]);
      ctx.beginPath(); ctx.arc(cx, cy, r, START, START + SWEEP * p);
      ctx.strokeStyle = g; ctx.lineWidth = 10;
      ctx.lineCap = 'round'; ctx.stroke(); ctx.lineCap = 'butt';
    }
  }

  function ring(cv, { days, total = 14 } = {}) {
    const w = cv.clientWidth || 52, h = cv.clientHeight || 52;
    const ctx = setup(cv, w, h);
    const cx = w / 2, cy = h / 2, r = Math.min(w, h) / 2 - 4;
    const p = clamp((total - (days || 0)) / total, 0, 1);

    ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.strokeStyle = 'rgba(255,255,255,0.07)'; ctx.lineWidth = 3.5;
    ctx.setLineDash([2, 3]); ctx.stroke(); ctx.setLineDash([]);

    if (p > 0) {
      ctx.beginPath(); ctx.arc(cx, cy, r, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * p);
      const col = p < 0.5 ? '#34d399' : p < 0.85 ? '#fbbf24' : '#f87171';
      ctx.strokeStyle = col; ctx.lineWidth = 3.5; ctx.lineCap = 'round'; ctx.stroke();
    }
  }

  function spark(cv, series = [], color = '#5B7FFF') {
    const w = cv.clientWidth || 80, h = cv.clientHeight || 28;
    if (!series.length) return;
    const ctx = setup(cv, w, h);
    const mn = Math.min(...series), mx = Math.max(...series);
    const range = mx - mn || 1;
    const pts = series.map((v, i) => [
      (i / (series.length - 1)) * w,
      h - ((v - mn) / range) * (h - 4) - 2,
    ]);

    const g = ctx.createLinearGradient(0, 0, 0, h);
    g.addColorStop(0, color.replace(')', ',0.18)').replace('rgb', 'rgba'));
    g.addColorStop(1, 'transparent');

    ctx.beginPath();
    pts.forEach(([x, y], i) => i ? ctx.lineTo(x, y) : ctx.moveTo(x, y));
    ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath();
    ctx.fillStyle = g; ctx.fill();

    ctx.beginPath();
    pts.forEach(([x, y], i) => i ? ctx.lineTo(x, y) : ctx.moveTo(x, y));
    ctx.strokeStyle = color; ctx.lineWidth = 1.5; ctx.lineJoin = 'round'; ctx.stroke();
  }

  function seal(cv, { id = '' } = {}) {
    const w = cv.clientWidth || 40, h = cv.clientHeight || 40;
    const ctx = setup(cv, w, h);
    const cx = w / 2, cy = h / 2, r = Math.min(w, h) / 2 - 2;
    let hash = 0;
    for (let i = 0; i < id.length; i++) hash = (Math.imul(31, hash) + id.charCodeAt(i)) | 0;

    const sides = 6 + (Math.abs(hash) % 3);
    ctx.beginPath();
    for (let i = 0; i < sides; i++) {
      const a = (Math.PI * 2 * i) / sides - Math.PI / 2;
      const rr = r * (0.88 + (Math.sin(hash * (i + 1)) * 0.12));
      i ? ctx.lineTo(cx + Math.cos(a) * rr, cy + Math.sin(a) * rr)
        : ctx.moveTo(cx + Math.cos(a) * rr, cy + Math.sin(a) * rr);
    }
    ctx.closePath();
    ctx.strokeStyle = 'rgba(245,200,107,0.55)'; ctx.lineWidth = 1.2; ctx.stroke();

    ctx.beginPath(); ctx.arc(cx, cy, r * 0.38, 0, Math.PI * 2);
    ctx.strokeStyle = 'rgba(245,200,107,0.35)'; ctx.lineWidth = 1; ctx.stroke();
  }

  function hydrate(root = document) {
    $$('[data-paint]', root).forEach((cv) => {
      const cfg = cv.dataset.cfg ? JSON.parse(cv.dataset.cfg) : {};
      switch (cv.dataset.paint) {
        case 'notch': notch(cv, cfg); break;
        case 'arc':   arc(cv, cfg.pct); break;
        case 'ring':  ring(cv, cfg); break;
        case 'spark': spark(cv, cfg.series, cfg.color); break;
        case 'seal':  seal(cv, cfg.id); break;
      }
    });
  }

  let rz;
  window.addEventListener('resize', () => {
    clearTimeout(rz);
    rz = setTimeout(() => {
      hydrate();
      const a = $('#arc');
      if (a && a.dataset.pct) arc(a, Number(a.dataset.pct));
    }, 140);
  }, { passive: true });

  return { notch, arc, ring, spark, seal, hydrate };
})();

/* ═══ 8 · REVENUE ══════════════════════════════════════════════════════ */

const PAYWALLS = {
  scan_quota: {
    eyebrow: 'Scan limit reached',
    h: 'You have used all 3 free analyses',
    d: 'Your infrastructure changes every week. A one-off scan finds yesterday\'s threats — <b>continuous enforcement</b> finds them the hour they ship.',
  },
  evidence: {
    eyebrow: 'Audit evidence',
    h: 'Sealed evidence packages are a paid feature',
    d: 'Auditors accept ACE packages as CC6.3 evidence because each one binds the threat, the reduction PR, the commit SHA and the approver into a hash-sealed artifact. Teams report <b>3.5 hours saved per control</b>.',
  },
  roles_limit: {
    eyebrow: 'Role tracking',
    h: 'Free tracks your first 5 roles',
    d: 'Dormant privilege is cumulative — the roles you are <b>not</b> watching are the ones that fail the audit. Track your whole estate and let the sweeper open reduction PRs automatically.',
  },
  github: {
    eyebrow: 'Repository import',
    h: 'Connect a repository to analyse continuously',
    d: 'Repository import scans every Terraform and IAM policy in your default branch, then <b>re-scans on every push</b> so drift is caught before it reaches production.',
  },
  export: {
    eyebrow: 'Auditor sharing',
    h: 'Share a read-only vault with your auditor',
    d: 'Stop emailing PDFs. Give your auditor a scoped, expiring link into the live vault and <b>cut a review cycle</b> out of the engagement.',
  },
};

const Revenue = (() => {

  function computeValue() {
    const { projects, roles } = Store.s;
    const evidencePacks = projects.length;
    const tracked       = roles.length;
    const autoPRs       = roles.filter((r) => r.state === 'PR_OPEN' || r.state === 'REDUCTION_READY').length;

    const evidenceHours = evidencePacks * CFG.hoursPerManualEvidencePack;
    const auditHours    = tracked * CFG.hoursPerManualRoleAudit;
    const labour        = (evidenceHours + auditHours) * CFG.blendedSecurityHourlyUSD;
    const avoided       = autoPRs * CFG.auditFindingCostUSD;

    return { total: labour + avoided, hours: evidenceHours + auditHours, autoPRs, evidencePacks, tracked };
  }

  function paintValue() {
    const el = $('#value-amount'), note = $('#value-note');
    if (!el) return;
    const v = computeValue();

    Motion.countTo(el, v.total, money);

    if (v.total <= 0) {
      note.textContent = 'Every automated reduction PR and sealed evidence package replaces manual audit preparation. Run your first analysis to start the counter.';
      return;
    }
    const bits = [`${v.hours.toFixed(1)} engineer-hours of manual evidence work automated`];
    if (v.autoPRs) bits.push(`${plural(v.autoPRs, 'CC6.3 exception')} remediated before the audit window`);
    note.innerHTML = esc(bits.join(' · ')) +
      (isPaid() ? '' : ` — <b>${esc(money(v.total))} of value on a free plan.</b>`);
  }

  function paintQuota() {
    const box = $('#quota'), val = $('#quota-v'), fill = $('#quota-fill'),
          cta = $('#quota-cta'), tag = $('#tag-plan');
    if (!box) return;

    if (isPaid()) {
      const name = PLANS.find((p) => p.id === Store.s.plan)?.name || 'Pro';
      box.className = 'quota';
      val.textContent = 'Unlimited';
      fill.style.width = '100%';
      cta.hidden = true;
      if (tag) { tag.textContent = name; tag.hidden = false; }
      return;
    }

    const used = clamp(Store.s.scansUsed, 0, CFG.freeScans);
    const left = CFG.freeScans - used;
    val.textContent = `${used} / ${CFG.freeScans}`;
    fill.style.width = (used / CFG.freeScans) * 100 + '%';
    box.className = 'quota' + (left === 0 ? ' zero' : left <= 1 ? ' low' : '');
    cta.hidden = false;
    cta.textContent = left === 0 ? 'Restore scanning' : left === 1 ? 'Last free scan — upgrade' : 'Unlock unlimited';
    if (tag) { tag.textContent = 'Free'; tag.hidden = false; }
  }

  function consumeScan() {
    if (isPaid()) return true;
    if (scansLeft() <= 0) { gate('scan_quota'); return false; }
    Store.set({ scansUsed: Store.s.scansUsed + 1 });
    disk.set('scansUsed', Store.s.scansUsed);
    paintQuota();
    track('scan_consumed', { remaining: scansLeft() });
    if (scansLeft() === 1) Toast.show('1 free analysis left this month.', 'warn');
    if (scansLeft() === 0) Toast.show('Free analyses used. Upgrade to keep scanning.', 'aurum');
    return true;
  }

  function veil(innerHTML, key) {
    const c = PAYWALLS[key] || PAYWALLS.evidence;
    return `
      <div class="gate">
        <div class="gate-veil" aria-hidden="true">${innerHTML}</div>
        <div class="gate-panel">
          <div class="gate-in">
            <svg class="gate-ic" viewBox="0 0 38 38" fill="none" aria-hidden="true">
              <rect x="8" y="16.5" width="22" height="15" rx="3.2" stroke="#F5C86B" stroke-width="1.5"/>
              <path d="M13 16.5v-4a6 6 0 0 1 12 0v4" stroke="#F5C86B" stroke-width="1.5" stroke-linecap="round"/>
              <circle cx="19" cy="23.5" r="1.9" fill="#F5C86B"/>
            </svg>
            <h3 class="gate-h">${esc(c.h)}</h3>
            <p class="gate-p">${c.d}</p>
            <button class="btn btn--aurum magnetic" data-cta="veil-${escAttr(key)}">
              View plans
            </button>
          </div>
        </div>
      </div>`;
  }

  function gate(key = 'scan_quota') {
    const c = PAYWALLS[key] || PAYWALLS.scan_quota;
    $('#paywall-eyebrow').textContent = c.eyebrow;
    $('#paywall-h').textContent = c.h;
    $('#paywall-d').innerHTML = c.d;
    renderPlans($('#paywall-plans'));

    const sc = $('#paywall');
    sc.hidden = false; sc.classList.add('on');
    document.body.style.overflow = 'hidden';
    Motion.magnetize(sc);
    setTimeout(() => $('#paywall-x')?.focus(), 60);
    track('paywall_view', { trigger: key });
  }

  function closeGate() {
    const sc = $('#paywall');
    sc.classList.remove('on'); sc.hidden = true;
    document.body.style.overflow = '';
    track('paywall_dismiss');
  }

  function renderPlans(host) {
    if (!host) return;
    const annual = Store.s.cycle === 'annual';

    host.innerHTML = PLANS.map((p) => {
      const price = annual ? p.annual : p.monthly;
      const priceBlock = p.custom
        ? `<div class="plan-price"><span class="plan-amt">${esc(p.custom)}</span></div>
           <div class="plan-note">Volume &amp; deployment based</div>`
        : `<div class="plan-price">
             <span class="plan-cur">$</span>
             <span class="plan-amt">${price}</span>
             <span class="plan-per">/ month</span>
           </div>
           <div class="plan-note">${annual
             ? `Billed annually · save $${(p.monthly - p.annual) * 12}/yr`
             : 'Billed monthly · cancel anytime'}</div>`;

      return `
        <div class="plan ${p.anchor ? 'plan--anchor' : ''}">
          ${p.flag ? `<span class="plan-flag">${esc(p.flag)}</span>` : ''}
          <div class="plan-n">${esc(p.name)}</div>
          <div class="plan-for">${esc(p.for)}</div>
          ${priceBlock}
          <ul class="plan-feats">${p.features.map((f) => `<li>${esc(f)}</li>`).join('')}</ul>
          <button class="btn ${p.anchor ? 'btn--aurum' : ''} btn--block magnetic"
                  data-checkout="${escAttr(p.id)}">
            ${p.custom ? 'Talk to sales' : `Start with ${esc(p.name)}`}
          </button>
        </div>`;
    }).join('');

    Motion.magnetize(host);
  }

  async function checkout(planId) {
    const plan = PLANS.find((p) => p.id === planId);
    if (!plan) return;
    track('checkout_start', { plan: planId, cycle: Store.s.cycle });

    if (plan.custom) {
      location.href = `mailto:sales@ace.security?subject=${encodeURIComponent('ACE Enterprise enquiry')}`;
      return;
    }
    if (!jwt()) {
      Toast.show('Sign in first so we can attach the subscription to your workspace.', 'warn');
      Auth.signIn();
      return;
    }

    Toast.show('Opening secure checkout…', 'aurum');
    try {
      const res = await Gateway.mutate('/api/billing/checkout', {
        body: { plan: planId, cycle: Store.s.cycle, return_url: location.origin },
        retries: 0,
      });
      const url = safeUrl(res?.url || res?.checkout_url);
      if (url) { track('checkout_redirect', { plan: planId }); location.href = url; return; }
      throw new Error('No checkout URL returned');
    } catch (e) {
      track('checkout_fallback', { plan: planId, reason: e.message });
      Toast.show('Checkout is finalising — our team will email you a payment link.', 'aurum');
      Gateway.mutate('/api/billing/intent', {
        body: { plan: planId, cycle: Store.s.cycle, email: Store.s.session?.user?.email || null },
        retries: 0,
      }).catch(() => {});
    }
  }

  return { paintValue, paintQuota, consumeScan, veil, gate, closeGate, renderPlans, checkout, computeValue };
})();

/* ═══ 9 · VIEWS ════════════════════════════════════════════════════════ */

const emptyState = (icon, h, p, action) => `
  <div class="empty">
    ${icon}
    <h3>${esc(h)}</h3>
    <p>${esc(p)}</p>
    ${action || ''}
  </div>`;

const ICON = {
  shield: `<svg viewBox="0 0 44 44" fill="none"><path d="M22 4 38 11v11c0 9-6.6 15.4-16 18-9.4-2.6-16-9-16-18V11L22 4Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M15 22.5l5 5 9-10" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  lock:   `<svg viewBox="0 0 44 44" fill="none"><rect x="10" y="19" width="24" height="17" rx="3.5" stroke="currentColor" stroke-width="1.4"/><path d="M15.5 19v-4.5a6.5 6.5 0 0 1 13 0V19" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>`,
  doc:    `<svg viewBox="0 0 44 44" fill="none"><rect x="10" y="6" width="24" height="32" rx="3" stroke="currentColor" stroke-width="1.4"/><path d="M16 15h12M16 22h12M16 29h7" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>`,
  alert:  `<svg viewBox="0 0 44 44" fill="none"><path d="M22 6 40 37H4L22 6Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M22 18v8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="22" cy="31" r="1.5" fill="currentColor"/></svg>`,
};

const signInGate = (what) => emptyState(
  ICON.lock, `Sign in to view ${what}`,
  'Your workspace is scoped to your account. Sign in with Google — it takes one click.',
  `<button class="btn btn--primary magnetic" data-signin>Sign in with Google</button>`
);

const SEV = (s) => ({ Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low' }[s] || 'low');

const Views = (() => {

  async function overview(force = false) {
    const deck = $('#deck');
    if (!jwt()) {
      deck.innerHTML = `<div style="grid-column:1/-1">${signInGate('your dashboard')}</div>`;
      $('#arc-pct').textContent = '—';
      $('#arc-cap').textContent = 'Sign in to compute your CC6.3 readiness score.';
      $('#ledger').innerHTML = `<p style="font-size:13px;color:var(--ink-4)">No activity yet.</p>`;
      Revenue.paintValue();
      Motion.magnetize(deck);
      return;
    }

    try {
      const [pRes, rRes] = await Gateway.all(
        ['/api/projects', '/api/ace/sweeper-status'],
        { scope: 'overview', force, onFresh: () => overview(false) }
      );

      const projects = (pRes.ok && pRes.data?.projects) || [];
      const roles    = (rRes.ok && rRes.data?.roles)    || [];
      Store.set({ projects, roles });

      const pending = roles.filter((r) => r.state === 'PENDING_REDUCTION').length;
      const open    = roles.filter((r) => r.state === 'PR_OPEN').length;
      const active  = roles.filter((r) => r.state === 'ACTIVE').length;
      const total   = roles.length;
      const pct     = total ? Math.round((active / total) * 100) : (projects.length ? 100 : 0);

      deck.classList.add('stagger');
      deck.innerHTML = [
        { k: 'Projects',       v: projects.length, cls: 'lumen', d: 'Analysed estates' },
        { k: 'Roles Tracked',  v: total,           cls: '',      d: `${active} active · ${pending} cooling off` },
        { k: 'Open PRs',       v: open,            cls: open ? 'warn' : 'ok', d: 'Awaiting merge' },
        { k: 'Needs Review',   v: pending,         cls: pending ? 'crit' : 'ok', d: 'In cooling-off window' },
      ].map((m, i) => `
        <div class="metric" style="--i:${i}">
          <div class="metric-k">${esc(m.k)}</div>
          <div class="metric-v ${m.cls}"><span class="roll" data-count="${m.v}">0</span></div>
          <div class="metric-d">${esc(m.d)}</div>
          <canvas class="metric-spark" data-paint="spark"
                  data-cfg='${escAttr(JSON.stringify({ series: trend(m.v), color: '#5B7FFF' }))}'></canvas>
        </div>`).join('');

      $$('[data-count]', deck).forEach((el) => Motion.countTo(el, Number(el.dataset.count)));

      const arcEl = $('#arc');
      arcEl.dataset.pct = pct;
      animateArc(arcEl, pct);
      $('#arc-pct').textContent = pct + '%';
      $('#arc-pct').style.color = pct >= 85 ? 'var(--ok)' : pct >= 60 ? 'var(--warn)' : 'var(--crit)';
      $('#arc-cap').textContent = !total
        ? 'No roles tracked yet. Run an analysis to compute readiness.'
        : pct === 100
          ? 'All tracked roles are active — no dormant privilege detected.'
          : `${plural(total - active, 'role')} need attention before your audit window closes.`;

      const feed = [
        pending && { c: 'warn',  t: `${plural(pending, 'role')} in cooling-off period`, s: 'Live' },
        open    && { c: 'lumen', t: `${plural(open, 'reduction PR')} open`,             s: 'Awaiting merge' },
        projects.length && { c: 'ok', t: `${plural(projects.length, 'project')} analysed`, s: 'Up to date' },
        { c: 'lumen', t: 'ACE sweeper running', s: 'Continuous' },
      ].filter(Boolean);

      $('#ledger').innerHTML = feed.map((f) => `
        <div class="ledger-row">
          <span class="led led--${f.c}"></span>
          <span class="ledger-t">${esc(f.t)}</span>
          <span class="ledger-s">${esc(f.s)}</span>
        </div>`).join('');

      Paint.hydrate(deck);
      Motion.spotlight(deck);
      Motion.magnetize(deck);
      Revenue.paintValue();

    } catch (e) {
      if (Gateway.isAbort(e)) return;
      if (e.message === 'AUTH_REQUIRED') {
        deck.innerHTML = `<div style="grid-column:1/-1">${signInGate('your dashboard')}</div>`;
        return;
      }
      deck.innerHTML = `<div style="grid-column:1/-1">${emptyState(ICON.alert, 'Could not load overview', e.message)}</div>`;
    }
  }

  function trend(v) {
    const base = Math.max(0, v - 3);
    return Array.from({ length: 8 }, (_, i) => base + Math.round(Math.random() * Math.max(1, v * 0.4) * (i / 7)));
  }

  function animateArc(el, pct) {
    if (!el) return;
    let cur = 0;
    const target = pct;
    const step = () => {
      cur = Math.min(cur + 2, target);
      Paint.arc(el, cur);
      if (cur < target) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  async function roles(force = false) {
    const el = $('#roles-list');
    if (!jwt()) { el.innerHTML = signInGate('IAM roles'); Motion.magnetize(el); return; }

    el.innerHTML = skeletons(3, 72);

    try {
      const data = await Gateway.get('/api/ace/sweeper-status', { scope: 'roles', force });
      const roles = data?.roles || [];
      Store.set({ roles });
      Revenue.paintValue();

      if (!roles.length) {
        el.innerHTML = emptyState(ICON.shield, 'No roles tracked yet',
          'Run ace analyze in your CI pipeline to start monitoring IAM roles.',
          `<button class="btn btn--primary magnetic" data-go="generate">New analysis</button>`);
        Motion.magnetize(el);
        return;
      }

      const stateClass = (s) => ({ ACTIVE: 'ok', PENDING_REDUCTION: 'warn', REDUCTION_READY: 'high', PR_OPEN: 'lumen' }[s] || 'ok');
      const stateLabel = (s) => ({ ACTIVE: 'Active', PENDING_REDUCTION: 'Cooling off', REDUCTION_READY: 'Ready', PR_OPEN: 'PR Open' }[s] || s);

      const visible = isPaid() ? roles : roles.slice(0, CFG.freeRoles);
      const veiled  = !isPaid() && roles.length > CFG.freeRoles;

      const cards = visible.map((r, i) => `
        <div class="role" style="--i:${Math.min(i, 16)}">
          <div class="role-state state--${stateClass(r.state)}"></div>
          <div style="min-width:0">
            <div class="role-n">${esc(r.role_name || r.role_arn)}</div>
            <div class="role-r">${esc(r.repo || '—')}</div>
          </div>
          <div style="text-align:right;flex-shrink:0">
            <span class="pill pill--${stateClass(r.state)} pill--xs">${stateLabel(r.state)}</span>
            ${r.state === 'PENDING_REDUCTION' && r.days_until_pr !== null
              ? `<div style="margin-top:5px">
                   <canvas class="role-ring" data-paint="ring"
                           data-cfg='${escAttr(JSON.stringify({ days: r.days_until_pr, total: 14 }))}' width="40" height="40"></canvas>
                   <div style="font-size:10px;color:var(--ink-4);margin-top:2px">${r.days_until_pr}d left</div>
                 </div>` : ''}
            ${r.state === 'PR_OPEN' && r.pr_url
              ? `<a href="${esc(safeUrl(r.pr_url))}" target="_blank" rel="noopener noreferrer"
                    class="btn btn--sm" style="margin-top:6px">View PR →</a>` : ''}
          </div>
        </div>`).join('');

      el.innerHTML = veiled
        ? Revenue.veil(`<div class="stagger">${cards}</div>`, 'roles_limit')
        : `<div class="stagger">${cards}</div>`;

      Paint.hydrate(el);
      Motion.magnetize(el);

    } catch (e) {
      if (Gateway.isAbort(e)) return;
      el.innerHTML = emptyState(ICON.alert, 'Could not load roles', e.message);
    }
  }

  async function threats(force = false) {
    const el = $('#threats-list');
    if (!jwt()) { el.innerHTML = signInGate('threats'); Motion.magnetize(el); return; }

    el.innerHTML = skeletons(2, 120);

    try {
      const data = await Gateway.get('/api/projects', { scope: 'threats', force });
      const projects = data?.projects || [];
      Store.set({ projects });
      syncFilter(projects);

      const filterPid = $('#filter-project')?.value || '';
      const filterSev = $('#filter-sev')?.value || '';
      const filtered  = filterPid ? projects.filter((p) => p.id === filterPid) : projects;

      if (!filtered.length) {
        el.innerHTML = emptyState(ICON.shield, 'No projects yet',
          'Run a new analysis to start finding threats.',
          `<button class="btn btn--primary magnetic" data-go="generate">New analysis</button>`);
        Motion.magnetize(el);
        return;
      }

      const results = await Gateway.all(
        filtered.map((p) => `/api/projects/${encodeURIComponent(p.id)}`),
        { scope: 'threats' }
      );

      let failed = 0;
      const all = [];
      results.forEach((r, i) => {
        if (!r.ok) { failed++; return; }
        (r.data?.threats || []).forEach((t) => {
          all.push({ ...t, _project: filtered[i].name, _pid: filtered[i].id });
        });
      });

      let shown = all.sort((a, b) => {
        const rank = { Critical: 0, High: 1, Medium: 2, Low: 3 };
        return (rank[a.severity] ?? 4) - (rank[b.severity] ?? 4);
      });

      if (filterSev) shown = shown.filter((t) => t.severity === filterSev);

      if (!shown.length) {
        el.innerHTML = emptyState(ICON.shield, 'No threats found',
          'No STRIDE threats match the current filter.');
        return;
      }

      const crit = shown.filter((t) => t.severity === 'Critical' || t.severity === 'High').length;

      const banner = crit && !isPaid() ? `
        <div class="value-meter" style="margin-bottom:var(--s-5)">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap">
            <div>
              <div class="value-k" style="margin-bottom:4px">${plural(crit, 'critical exception')} open</div>
              <div style="font-size:13px;color:var(--ink-2);max-width:52ch">
                Remediated late, these cost roughly <b style="color:var(--aurum)">${esc(money(crit * CFG.auditFindingCostUSD))}</b> in audit rework. ACE opens the reduction PRs automatically.
              </div>
            </div>
            <button class="btn btn--aurum magnetic" data-cta="threat-banner">Automate remediation</button>
          </div>
        </div>` : '';

      el.innerHTML = banner +
        `<div class="sec">${plural(shown.length, 'threat')} identified${failed ? ` · ${failed} project(s) unavailable` : ''}</div>` +
        `<div class="stagger">${shown.map((t, i) => threatCard(t, i, true)).join('')}</div>`;

      if (failed) Toast.show(`${failed} project(s) could not be loaded — showing the rest.`, 'warn');

      Motion.magnetize(el);
      Motion.observe(el);

    } catch (e) {
      if (Gateway.isAbort(e)) return;
      if (e.message === 'AUTH_REQUIRED') { el.innerHTML = signInGate('threats'); return; }
      el.innerHTML = emptyState(ICON.alert, 'Could not load threats', e.message);
    }
  }

  function syncFilter(projects) {
    const sel = $('#filter-project');
    const have = new Set(Array.from(sel.options).map((o) => o.value));
    projects.forEach((p) => {
      if (have.has(p.id)) return;
      const o = document.createElement('option');
      o.value = p.id; o.textContent = p.name;
      sel.appendChild(o);
    });
  }

  function threatCard(t, i, live) {
    const s = SEV(t.severity);
    const controls = live && t.id ? `
      <div class="threat-act">
        <select class="field-w" style="font-size:12px" data-threat-status="${escAttr(t.id)}" aria-label="Threat status">
          ${['pending', 'accepted', 'rejected'].map((v) =>
            `<option value="${v}" ${t.status === v ? 'selected' : ''}>${v[0].toUpperCase() + v.slice(1)}</option>`).join('')}
        </select>
        <select class="field-w" style="font-size:12px" data-threat-rem="${escAttr(t.id)}" aria-label="Remediation status">
          ${[['not_started', 'Not started'], ['in_progress', 'In progress'], ['resolved', 'Resolved']].map(([v, l]) =>
            `<option value="${v}" ${t.remediation_status === v ? 'selected' : ''}>${l}</option>`).join('')}
        </select>
        ${(s === 'critical' || s === 'high') && !isPaid()
          ? `<span class="threat-val push">${esc(money(CFG.auditFindingCostUSD))} audit exposure</span>` : ''}
      </div>` : '';

    return `
      <div class="threat ${s}" style="--i:${Math.min(i, 16)}">
        <div class="threat-top">
          <div>
            ${t._project ? `<div class="threat-src">${esc(t._project)}</div>` : ''}
            <div class="threat-h">${esc(t.title)}</div>
          </div>
          <div class="col" style="align-items:flex-end;gap:5px">
            <span class="pill pill--${s === 'critical' ? 'crit' : s === 'high' ? 'high' : s === 'medium' ? 'warn' : 'ok'} pill--xs">${esc(t.severity)}</span>
            ${t.status ? `<span class="pill pill--mute pill--xs">${esc(t.status)}</span>` : ''}
          </div>
        </div>
        <div class="threat-m">
          <span>${esc(t.category)}</span><span>·</span><span>${esc(t.affected_component)}</span>
        </div>
        <div class="threat-c">${esc(t.soc2_control)}${t.iso27001_control ? ` · ISO ${esc(t.iso27001_control)}` : ''}${t.nist_control ? ` · NIST ${esc(t.nist_control)}` : ''}</div>
        <div class="threat-d">${esc(t.description)}</div>
        ${Array.isArray(t.mitigations) && t.mitigations.length
          ? `<ul class="mit">${t.mitigations.slice(0, 3).map((m) => `<li>${esc(m.description || m)}</li>`).join('')}</ul>` : ''}
        ${controls}
      </div>`;
  }

  function renderResult(model, containerId) {
    const el = $('#' + containerId);
    if (!el) return;
    if (!model?.threats?.length) {
      el.innerHTML = emptyState(ICON.shield, 'No threats found',
        'No STRIDE threats were identified in this architecture.');
      return;
    }
    const list = [...model.threats].sort((a, b) => {
      const r = { Critical: 0, High: 1, Medium: 2, Low: 3 };
      return (r[a.severity] ?? 4) - (r[b.severity] ?? 4);
    });
    const crit = list.filter((t) => t.severity === 'Critical' || t.severity === 'High').length;

    el.innerHTML = `
      <div class="sec">${plural(list.length, 'threat')} identified</div>
      <div class="glass pad-sm" style="margin-bottom:var(--s-4);font-size:13px;color:var(--ink-2);line-height:1.7">
        ${esc(model.system_summary)}
      </div>
      <div class="stagger">${list.map((t, i) => threatCard(t, i, false)).join('')}</div>
      ${!isPaid() ? `
        <div class="value-meter" style="margin-top:var(--s-5)">
          <div class="value-k">What happens next</div>
          <div style="font-size:14px;color:var(--ink);line-height:1.7;max-width:60ch;margin-top:6px">
            This snapshot is accurate today. On a paid plan ACE re-scans on every push, opens
            reduction PRs after 14 days of dormancy, and seals each fix into an auditor-ready
            CC6.3 package — ${crit ? `starting with the ${plural(crit, 'high-severity finding')} above.` : 'automatically.'}
          </div>
          <div class="row" style="margin-top:var(--s-5)">
            <button class="btn btn--aurum magnetic" data-cta="post-analysis">Automate this</button>
            <button class="btn btn--ghost" data-go="pricing">Compare plans</button>
          </div>
        </div>` : ''}`;

    Motion.magnetize(el);
    Motion.observe(el);
    if (!isPaid()) track('paywall_tease', { surface: 'post_analysis', threats: list.length });
    el.scrollIntoView({ behavior: REDUCED ? 'auto' : 'smooth', block: 'start' });
  }

  async function evidence(force = false) {
    const el = $('#evidence-list');
    if (!jwt()) { el.innerHTML = signInGate('evidence packages'); Motion.magnetize(el); return; }

    el.innerHTML = skeletons(2, 88);

    try {
      const data = await Gateway.get('/api/projects', { scope: 'evidence', force });
      const projects = data?.projects || [];
      Store.set({ projects });
      Revenue.paintValue();

      if (!projects.length) {
        el.innerHTML = emptyState(ICON.doc, 'No evidence packages yet',
          'Run an analysis and complete an IAM remediation to generate your first sealed CC6.3 package.',
          `<button class="btn btn--primary magnetic" data-go="generate">New analysis</button>`);
        Motion.magnetize(el);
        return;
      }

      const card = (p, i) => `
        <div class="ev" style="--i:${Math.min(i, 16)}">
          <canvas class="ev-seal" data-paint="seal" data-cfg='${escAttr(JSON.stringify({ id: p.id }))}'></canvas>
          <div style="min-width:0">
            <div class="ev-n">${esc(p.name)}</div>
            <div class="ev-m">
              <span>CC6.3 evidence package</span><span>·</span>
              <span>${esc(dateShort(p.created_at))}</span>
              <span class="sha">${esc(String(p.id || '').slice(0, 8) || 'unsealed')}</span>
            </div>
          </div>
          <div class="row">
            ${isPaid()
              ? `<button class="btn btn--sm" data-pdf="${escAttr(p.id)}" data-pdf-name="${escAttr(p.name)}">
                   <svg width="12" height="12" viewBox="0 0 12 12" fill="none" aria-hidden="true">
                     <path d="M6 1v7M3.2 5.6 6 8.4l2.8-2.8M1.6 10.4h8.8" stroke="currentColor" stroke-width="1.35" stroke-linecap="round" stroke-linejoin="round"/>
                   </svg> Download PDF
                 </button>`
              : `<button class="btn btn--aurum btn--sm magnetic" data-cta="evidence-row">Unlock</button>`}
          </div>
        </div>`;

      if (isPaid()) {
        el.innerHTML = `<div class="stagger">${projects.map(card).join('')}</div>`;
      } else {
        el.innerHTML = Revenue.veil(projects.slice(0, 4).map(card).join(''), 'evidence');
        track('paywall_tease', { surface: 'evidence', packages: projects.length });
      }

      Paint.hydrate(el);
      Motion.magnetize(el);

    } catch (e) {
      if (Gateway.isAbort(e)) return;
      el.innerHTML = emptyState(ICON.alert, 'Could not load evidence', e.message);
    }
  }

  async function downloadPdf(pid, name) {
    if (!isPaid()) { Revenue.gate('evidence'); return; }
    if (!jwt())    { Toast.show('Sign in first', 'err'); return; }
    track('evidence_download', { project: pid });
    Toast.show('Sealing evidence package…');
    try {
      const blob = await Gateway.raw(`/api/projects/${encodeURIComponent(pid)}/evidence-pdf`, { retries: 1 });
      if (!(blob instanceof Blob)) throw new Error('Unexpected response');
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `ace-evidence-${String(name || 'package').toLowerCase().replace(/[^a-z0-9]+/g, '-')}.pdf`;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1500);
      Toast.show('Evidence package downloaded', 'ok');
    } catch (e) {
      Toast.show(e.message, 'err');
    }
  }

  function pricing() {
    const host = $('#pricing-page');
    if (host.dataset.built) { Revenue.renderPlans($('#pricing-plans')); return; }
    host.dataset.built = '1';
    host.innerHTML = `
      <div class="cycle" role="group" aria-label="Billing cycle" style="margin-bottom:var(--s-6)">
        <button class="cycle-b on" data-cycle="monthly">Monthly</button>
        <button class="cycle-b" data-cycle="annual">Annual<span class="cycle-save">−20%</span></button>
      </div>
      <div class="plans" id="pricing-plans"></div>
      <div class="modal-foot" style="margin-top:var(--s-8)">
        <span class="trust">SOC 2 Type II infrastructure</span>
        <span class="trust">Cancel anytime</span>
        <span class="trust">Your code never leaves your VPC</span>
      </div>`;
    Revenue.renderPlans($('#pricing-plans'));
    track('pricing_view');
  }

  const skeletons = (n, h) => Array.from({ length: n },
    () => `<div class="skel" style="height:${h}px;border-radius:18px;margin-bottom:10px"></div>`).join('');

  return { overview, roles, threats, evidence, pricing, renderResult, downloadPdf, threatCard };
})();

/* ═══ 10 · CHROME ══════════════════════════════════════════════════════ */

const Toast = (() => {
  const HUE = { ok: 'var(--ok)', err: 'var(--crit)', warn: 'var(--warn)',
                aurum: 'var(--aurum)', info: 'var(--lumen)' };
  function show(msg, kind = 'info') {
    const host = $('#toasts');
    if (!host) return;
    const t = document.createElement('div');
    t.className = 'toast' + (kind === 'aurum' ? ' aurum' : '');
    t.setAttribute('role', kind === 'err' ? 'alert' : 'status');

    const dot = document.createElement('span');
    dot.className = 'toast-dot';
    dot.style.background = HUE[kind] || HUE.info;
    dot.style.boxShadow = `0 0 9px ${HUE[kind] || HUE.info}`;

    const txt = document.createElement('span');
    txt.textContent = msg;

    t.append(dot, txt);
    host.appendChild(t);

    setTimeout(() => {
      t.classList.add('out');
      t.addEventListener('animationend', () => t.remove(), { once: true });
      setTimeout(() => t.remove(), 600);
    }, CFG.toastMs);
  }
  return { show };
})();

const Router = (() => {
  const VIEWS = ['overview', 'roles', 'threats', 'generate', 'evidence', 'pricing'];

  function go(view, opts = {}) {
    if (!VIEWS.includes(view)) view = 'overview';
    if (view === Store.s.view && !opts.force) return;

    if (Store.s.view && Store.s.view !== view) Gateway.abortScope(Store.s.view);

    Store.set({ view });

    $$('.nav-i').forEach((n) => {
      const on = n.dataset.view === view;
      n.classList.toggle('on', on);
      on ? n.setAttribute('aria-current', 'page') : n.removeAttribute('aria-current');
    });
    $$('.view').forEach((v) => v.classList.toggle('on', v.id === `v-${view}`));

    $('#rail')?.classList.remove('open');
    $('#burger')?.setAttribute('aria-expanded', 'false');

    if (location.hash.slice(1) !== view) history.replaceState(null, '', '#' + view);
    window.scrollTo({ top: 0, behavior: REDUCED ? 'auto' : 'smooth' });

    track('view', { to: view });

    const load = { overview: Views.overview, roles: Views.roles, threats: Views.threats,
                   evidence: Views.evidence, pricing: Views.pricing }[view];
    if (load) load(!!opts.force);

    Motion.observe($(`#v-${view}`) || document);
    Motion.magnetize($(`#v-${view}`) || document);
  }

  const boot = () => {
    const h = location.hash.slice(1);
    go(VIEWS.includes(h) ? h : 'overview', { force: true });
    window.addEventListener('hashchange', () => go(location.hash.slice(1)));
  };

  return { go, boot };
})();

const Cmdk = (() => {
  let idx = 0, items = [];

  const COMMANDS = () => [
    { label: 'Overview',            hint: 'View',    run: () => Router.go('overview') },
    { label: 'IAM Roles',           hint: 'View',    run: () => Router.go('roles') },
    { label: 'Threats',             hint: 'View',    run: () => Router.go('threats') },
    { label: 'New Analysis',        hint: 'View',    run: () => Router.go('generate') },
    { label: 'Evidence Vault',      hint: 'View',    run: () => Router.go('evidence') },
    { label: 'Refresh all data',    hint: 'Action',  run: () => { Gateway.invalidate(); Router.go(Store.s.view, { force: true }); Toast.show('Refreshed', 'ok'); } },
    ...(isPaid() ? [] : [{ label: 'Upgrade plan', hint: 'Billing', aurum: true, run: () => Revenue.gate('scan_quota') }]),
    { label: 'Compare plans',       hint: 'Billing', aurum: true, run: () => Router.go('pricing') },
    ...(Store.s.session
      ? [{ label: 'Sign out', hint: 'Account', run: () => Auth.signOut() }]
      : [{ label: 'Sign in with Google', hint: 'Account', run: () => Auth.signIn() }]),
  ];

  function open() {
    const box = $('#cmdk');
    box.hidden = false; box.classList.add('on');
    $('#cmdk-in').value = ''; idx = 0;
    render('');
    setTimeout(() => $('#cmdk-in').focus(), 40);
    track('cmdk_open');
  }
  function close() {
    const box = $('#cmdk');
    box.classList.remove('on'); box.hidden = true;
  }
  const isOpen = () => $('#cmdk')?.classList.contains('on');

  function render(q) {
    const needle = q.trim().toLowerCase();
    items = COMMANDS().filter((c) =>
      !needle || c.label.toLowerCase().includes(needle) || c.hint.toLowerCase().includes(needle));
    idx = clamp(idx, 0, Math.max(0, items.length - 1));

    const list = $('#cmdk-list');
    if (!items.length) {
      list.innerHTML = `<div class="cmdk-i" style="opacity:.5">No matches</div>`;
      return;
    }
    list.innerHTML = items.map((c, i) => `
      <div class="cmdk-i${i === idx ? ' on' : ''}${c.aurum ? ' aurum' : ''}" data-cmd="${i}" role="option" aria-selected="${i === idx}">
        <span>${esc(c.label)}</span>
        <span class="cmdk-hint">${esc(c.hint)}</span>
      </div>`).join('');
  }

  function move(d) { idx = clamp(idx + d, 0, items.length - 1); render($('#cmdk-in').value); }
  function run(i)  { const c = items[i ?? idx]; if (c) { close(); c.run(); } }

  return { open, close, isOpen, render, move, run };
})();

/* ═══ Generate view ════════════════════════════════════════════════════ */

const Generate = (() => {

  function tabs() {
    $$('[data-tab]').forEach((btn) => {
      btn.addEventListener('click', () => {
        $$('[data-tab]').forEach((b) => b.classList.remove('on'));
        btn.classList.add('on');
        $$('.pane').forEach((p) => p.classList.remove('on'));
        $(`#pane-${btn.dataset.tab}`)?.classList.add('on');
        track('tab_switch', { tab: btn.dataset.tab });
      });
    });
  }

  function dropzone() {
    const zone = $('#drop-zone'), input = $('#file-input');
    if (!zone || !input) return;

    zone.addEventListener('click', () => input.click());
    zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('drag'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('drag'));
    zone.addEventListener('drop', (e) => {
      e.preventDefault(); zone.classList.remove('drag');
      const f = e.dataTransfer.files[0]; if (f) handleFile(f);
    });
    input.addEventListener('change', () => { if (input.files[0]) handleFile(input.files[0]); });
  }

  function setStatus(sel, msg, kind = '') {
    const el = $(sel);
    if (!el) return;
    el.textContent = msg;
    el.className = 'gen-status' + (kind ? ' ' + kind : '');
  }

  async function handleFile(file) {
    const allowed = ['.tf', '.hcl', '.yaml', '.yml', '.json', '.txt'];
    const lower = file.name.toLowerCase();
    const ok = lower === 'dockerfile' || lower.endsWith('dockerfile') ||
                allowed.some((e) => lower.endsWith(e));
    if (!ok) return setStatus('#st-file', 'Unsupported file type.', 'err');
    if (file.size > 100_000) return setStatus('#st-file', 'File too large (max 100 KB).', 'err');

    if (!jwt()) { setStatus('#st-file', 'Sign in to analyse files.', 'err'); Auth.signIn(); return; }
    if (!Revenue.consumeScan()) return;

    track('analysis_start', { source: 'file', name: file.name });
    setStatus('#st-file', 'Analysing ' + file.name + '…', 'busy');

    try {
      const fd = new FormData();
      fd.append('file', file);
      const name = $('#in-file-name')?.value.trim() || file.name;
      const data = await Gateway.mutate(
        `/api/generate-from-file?name=${encodeURIComponent(name)}`,
        { body: fd, retries: 0 }
      );
      const n = data?.threat_model?.threats?.length || 0;
      setStatus('#st-file', `${plural(n, 'threat')} found`, 'ok');
      Gateway.invalidate('/api/projects');
      Views.renderResult(data.threat_model, 'gen-out');
      Toast.show(`Analysis complete — ${plural(n, 'threat')} found`, 'ok');
      track('analysis_done', { source: 'file', threats: n });
    } catch (e) {
      setStatus('#st-file', e.message, 'err');
      Toast.show(e.message, 'err');
      track('analysis_error', { source: 'file', message: e.message });
    }
  }

  async function demo() {
    const desc = $('#in-desc')?.value.trim();
    if (!desc) return setStatus('#st-text', 'Describe your system first.', 'err');

    if (!jwt()) {
      if (Store.s.anonDemos >= CFG.freeAnonDemos) {
        setStatus('#st-text', 'Sign in to run more analyses.', 'err');
        track('anon_demo_exhausted');
        Auth.signIn();
        return;
      }
      Store.set({ anonDemos: Store.s.anonDemos + 1 });
      disk.set('anonDemos', Store.s.anonDemos);
    } else if (!Revenue.consumeScan()) {
      return setStatus('#st-text', 'Free scan limit reached.', 'err');
    }

    track('analysis_start', { source: 'text', chars: desc.length });
    setStatus('#st-text', 'Analysing architecture…', 'busy');

    try {
      const data = await Gateway.mutate('/api/demo', {
        auth: false, retries: 0,
        body: { name: $('#in-text-name')?.value.trim() || 'Demo', architecture_description: desc },
      });
      const n = data?.threat_model?.threats?.length || 0;
      setStatus('#st-text', `${plural(n, 'threat')} found`, 'ok');
      Views.renderResult(data.threat_model, 'gen-out');
      track('analysis_done', { source: 'text', threats: n });
      if (!jwt()) $('#demo-left').textContent = 'Sign in to save results';
    } catch (e) {
      setStatus('#st-text', e.message, 'err');
      track('analysis_error', { source: 'text', message: e.message });
    }
  }

  async function save() {
    const desc = $('#in-desc')?.value.trim();
    if (!desc) return setStatus('#st-text', 'Describe your system first.', 'err');
    if (!jwt()) { setStatus('#st-text', 'Sign in to save to your workspace.', 'err'); Auth.signIn(); return; }
    if (!Revenue.consumeScan()) return setStatus('#st-text', 'Free scan limit reached.', 'err');

    track('analysis_start', { source: 'save' });
    setStatus('#st-text', 'Saving to workspace…', 'busy');
    try {
      const data = await Gateway.mutate('/api/generate', {
        retries: 0,
        body: { name: $('#in-text-name')?.value.trim() || 'Untitled project', architecture_description: desc },
      });
      const n = data?.threat_model?.threats?.length || 0;
      setStatus('#st-text', `Saved · ${plural(n, 'threat')} found`, 'ok');
      Gateway.invalidate('/api/projects');
      Views.renderResult(data.threat_model, 'gen-out');
      Toast.show('Saved to workspace', 'ok');
      track('analysis_done', { source: 'save', threats: n });
    } catch (e) {
      setStatus('#st-text', e.message, 'err');
      Toast.show(e.message, 'err');
    }
  }

  async function github() {
    const raw = $('#in-gh-url')?.value.trim();
    if (!raw) return setStatus('#st-github', 'Enter a GitHub repository URL.', 'err');

    const url = safeUrl(raw);
    if (!url || !/(^|\.)github\.com$/i.test(new URL(url).hostname)) {
      return setStatus('#st-github', 'Enter a valid https://github.com/owner/repo URL.', 'err');
    }
    if (!jwt()) { setStatus('#st-github', 'Sign in to import a repository.', 'err'); Auth.signIn(); return; }

    if (!isPaid()) { Revenue.gate('github'); track('paywall_hit', { trigger: 'github' }); return; }

    track('analysis_start', { source: 'github' });
    setStatus('#st-github', 'Cloning and analysing repository…', 'busy');
    try {
      const data = await Gateway.mutate('/api/generate-from-github', {
        retries: 0,
        body: { name: $('#in-gh-name')?.value.trim() || 'GitHub import', repo_url: url },
      });
      const n = data?.threat_model?.threats?.length || 0;
      setStatus('#st-github', `${plural(n, 'threat')} found`, 'ok');
      Gateway.invalidate('/api/projects');
      Views.renderResult(data.threat_model, 'gen-out');
      Toast.show('Repository imported', 'ok');
      track('analysis_done', { source: 'github', threats: n });
    } catch (e) {
      setStatus('#st-github', e.message, 'err');
      Toast.show(e.message, 'err');
    }
  }

  function init() {
    tabs(); dropzone();
    $('#btn-demo')?.addEventListener('click', demo);
    $('#btn-save')?.addEventListener('click', save);
    $('#btn-github')?.addEventListener('click', github);
  }

  return { init };
})();

/* ═══ Threat mutations ══════════════════════════════════════════════════ */

async function patchThreat(id, field, value, selectEl) {
  if (!jwt()) { Toast.show('Sign in to update threats.', 'err'); return; }
  const path = field === 'status'
    ? `/api/threats/${encodeURIComponent(id)}/status`
    : `/api/threats/${encodeURIComponent(id)}/remediation`;

  const prev = selectEl?.dataset.prev ?? selectEl?.value;
  if (selectEl) selectEl.disabled = true;

  try {
    await Gateway.mutate(path, { method: 'PATCH', body: { status: value }, retries: 1 });
    Gateway.invalidate('/api/projects');
    if (selectEl) selectEl.dataset.prev = value;
    Toast.show(field === 'status'
      ? `Marked ${value}`
      : `Remediation: ${value.replace(/_/g, ' ')}`, 'ok');
    track('threat_update', { field, value });
  } catch (e) {
    if (selectEl && prev !== undefined) selectEl.value = prev;
    Toast.show(e.message, 'err');
  } finally {
    if (selectEl) selectEl.disabled = false;
  }
}

/* ═══ Global event delegation ═══════════════════════════════════════════ */

function wireDelegation() {

  document.addEventListener('click', (e) => {
    const t = e.target;

    const nav = t.closest('.nav-i[data-view]');
    if (nav) return Router.go(nav.dataset.view);

    const go = t.closest('[data-go]');
    if (go) return Router.go(go.dataset.go);

    const reload = t.closest('[data-reload]');
    if (reload) {
      Gateway.invalidate();
      return Router.go(reload.dataset.reload, { force: true });
    }

    const cta = t.closest('[data-cta]');
    if (cta) {
      track('upgrade_click', { source: cta.dataset.cta });
      const map = { 'rail-quota': 'scan_quota', 'evidence-row': 'evidence',
                    'threat-banner': 'scan_quota', 'post-analysis': 'scan_quota' };
      const key = map[cta.dataset.cta] ||
                  (cta.dataset.cta.startsWith('veil-') ? cta.dataset.cta.slice(5) : 'scan_quota');
      return Revenue.gate(key);
    }

    const co = t.closest('[data-checkout]');
    if (co) return Revenue.checkout(co.dataset.checkout);

    const cyc = t.closest('[data-cycle]');
    if (cyc) {
      Store.set({ cycle: cyc.dataset.cycle });
      $$('[data-cycle]').forEach((b) => b.classList.toggle('on', b.dataset.cycle === cyc.dataset.cycle));
      Revenue.renderPlans($('#paywall-plans'));
      Revenue.renderPlans($('#pricing-plans'));
      track('cycle_toggle', { cycle: cyc.dataset.cycle });
      return;
    }

    const pdf = t.closest('[data-pdf]');
    if (pdf) return Views.downloadPdf(pdf.dataset.pdf, pdf.dataset.pdfName);

    if (t.closest('[data-signin]') || t.closest('#acct')) {
      return Store.s.session ? Auth.signOut() : Auth.signIn();
    }

    if (t.closest('#btn-cmdk')) return Cmdk.open();
    if (t.closest('#paywall-x')) return Revenue.closeGate();
    if (t.id === 'paywall')      return Revenue.closeGate();
    if (t.id === 'cmdk')         return Cmdk.close();

    const cmd = t.closest('[data-cmd]');
    if (cmd) return Cmdk.run(Number(cmd.dataset.cmd));

    const burger = t.closest('#burger');
    if (burger) {
      const rail = $('#rail');
      const open = rail.classList.toggle('open');
      burger.setAttribute('aria-expanded', String(open));
      return;
    }
  });

  document.addEventListener('change', (e) => {
    const st = e.target.closest('[data-threat-status]');
    if (st) return patchThreat(st.dataset.threatStatus, 'status', st.value, st);

    const rem = e.target.closest('[data-threat-rem]');
    if (rem) return patchThreat(rem.dataset.threatRem, 'remediation', rem.value, rem);

    if (e.target.id === 'filter-project' || e.target.id === 'filter-sev') {
      track('threat_filter', { by: e.target.id, value: e.target.value });
      return Views.threats(false);
    }
  });

  document.addEventListener('keydown', (e) => {
    const focus = document.activeElement;

    if ((e.key === 'Enter' || e.key === ' ') && focus?.matches?.('.nav-i[data-view], #acct')) {
      e.preventDefault(); focus.click(); return;
    }

    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      return Cmdk.isOpen() ? Cmdk.close() : Cmdk.open();
    }

    if (Cmdk.isOpen()) {
      if (e.key === 'Escape')    { e.preventDefault(); return Cmdk.close(); }
      if (e.key === 'ArrowDown') { e.preventDefault(); return Cmdk.move(1); }
      if (e.key === 'ArrowUp')   { e.preventDefault(); return Cmdk.move(-1); }
      if (e.key === 'Enter')     { e.preventDefault(); return Cmdk.run(); }
      return;
    }

    if (e.key === 'Escape') {
      if ($('#paywall')?.classList.contains('on')) return Revenue.closeGate();
      if ($('#rail')?.classList.contains('open')) {
        $('#rail').classList.remove('open');
        $('#burger')?.setAttribute('aria-expanded', 'false');
      }
    }

    if (!/^(INPUT|TEXTAREA|SELECT)$/.test(focus?.tagName || '')) {
      if (e.key === 'g') { window.__g = true; setTimeout(() => { window.__g = false; }, 700); return; }
      if (window.__g) {
        const jump = { o: 'overview', r: 'roles', t: 'threats', n: 'generate', e: 'evidence', p: 'pricing' }[e.key];
        if (jump) { window.__g = false; e.preventDefault(); Router.go(jump); }
      }
    }
  });

  $('#cmdk-in')?.addEventListener('input', (e) => Cmdk.render(e.target.value));

  $('#paywall')?.addEventListener('keydown', (e) => {
    if (e.key !== 'Tab') return;
    const f = $$('button, [href], input, select, textarea', $('#paywall-modal'))
      .filter((el) => !el.disabled && el.offsetParent !== null);
    if (!f.length) return;
    const first = f[0], last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  });
}

/* ═══ 11 · BOOT ════════════════════════════════════════════════════════ */

function boot() {
  Motion.mesh();
  Motion.magnetize();
  Motion.spotlight();
  Motion.observe();

  wireDelegation();
  Generate.init();

  Revenue.paintQuota();
  Revenue.paintValue();

  Auth.init();
  Router.boot();

  Store.set({ booted: true });
  track('app_boot', { reducedMotion: REDUCED });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot, { once: true });
} else {
  boot();
}

/* Back-compat shims */
window.navigate             = (v) => Router.go(v);
window.toast                = (m, k) => Toast.show(m, k);
window.setThreatStatus      = (id, v) => patchThreat(id, 'status', v);
window.setThreatRemediation = (id, v) => patchThreat(id, 'remediation', v);
window.setStatus            = (_pid, id, v) => patchThreat(id, 'status', v);
window.setRemediation       = (_pid, id, v) => patchThreat(id, 'remediation', v);
window.downloadEvidence     = (pid, name) => Views.downloadPdf(pid, name);
window.getJwt               = () => jwt();
window._onSessionChange     = () => Auth.paint();
window._supaSignIn          = () => Auth.signIn();
window._supaSignOut         = () => Auth.signOut();
Object.defineProperty(window, '_supaSession', { get: () => Store.s.session });

window.ACE = { Store, Gateway, Revenue, Views, Router, Paint, Motion, Toast, CFG, PLANS, track };