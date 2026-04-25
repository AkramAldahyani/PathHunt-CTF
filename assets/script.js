/* ============================================
   PathHunt CTF — Main Script
   Shared navigation, progress, flag verification

   Security note: flags are NEVER stored in
   plaintext in this file. Only SHA-256 hashes
   live here. Users submit plaintext, we hash it,
   and compare. Solved-progress is keyed by hash
   too, so nothing in localStorage leaks a flag.
   ============================================ */

/* Resolve the project root once, so nav links work from any depth
   (e.g. /dev-panel/index.html → /dashboard.html, not /dev-panel/dashboard.html).
   - On a server (http/https): use a root-relative "/" prefix.
   - On file:// : derive an absolute file URL from this script's own src,
     since "/" would resolve to the OS filesystem root. */
const _base = (() => {
  if (window.location.protocol !== 'file:') {
    return '/';
  }
  const cur = document.currentScript ||
    Array.from(document.getElementsByTagName('script'))
      .find(s => s.src && /assets\/script\.js/.test(s.src));
  if (cur && cur.src) {
    return cur.src.replace(/assets\/script\.js(\?.*)?(#.*)?$/, '');
  }
  return '';
})();

// Debug marker — open DevTools → Console. If you don't see this line on
// /dev-panel/, the browser is serving a cached copy of the old script.js.
console.info('[PathHunt] script.js loaded. _base =', JSON.stringify(_base));

const PATHHUNT = {
  challenges: [
    {
      id: 1, slug: 'inspect-me-H3L', name: 'HTML Source',
      difficulty: 1, points: 100, path: 'inspect-me-H3L.html',
      desc: 'The beginning. Right-click and View Source to find what\'s hidden in plain sight.',
      hash: '89368948f94345165a64ae09cfd810fd6bef2cad1d61c25b48b8fbb3d8d2058e'
    },
    {
      id: 2, slug: 'hidden-entry-9xA', name: 'CSS Leak',
      difficulty: 1, points: 100, path: 'hidden-entry-9xA.html',
      desc: 'Stylesheets can hold secrets too. Check the linked CSS file carefully.',
      hash: '3108c2c1660a48f84358bb10b3924e80ae9947dc311cadd6324af67139e6c86a'
    },
    {
      id: 3, slug: 'js-vault-3kL', name: 'Base64 JavaScript',
      difficulty: 2, points: 150, path: 'js-vault-3kL.html',
      desc: 'JavaScript variables often hold encoded data. Decode the secret.',
      hash: '7f82f550148246ff410b9ce752ab58ab9b68f558421c37a6204a4502b8c5cb52'
    },
    {
      id: 4, slug: 'robot-zone', name: 'Robots Recon',
      difficulty: 2, points: 150, path: 'robot-zone.html',
      desc: 'Web crawlers have a map. Check what the site tells them not to index.',
      hash: '51862f98dd49f8bf4a1c9f1e78ea879340915913db24cfbe4b1336cf340dc6b2'
    },
    {
      id: 5, slug: 'admin-hidden', name: 'Directory Fuzzing',
      difficulty: 2, points: 150, path: 'admin-hidden.html',
      desc: 'Not every directory is linked. Can you guess the path?',
      hash: '15b467add265c86c30ec9afc227f97ffb628778969b966f239c789974ccc57e1'
    },
    {
      id: 6, slug: 'header-secret', name: 'HTTP Headers',
      difficulty: 3, points: 200, path: 'header-secret.html',
      desc: 'Servers send more than just HTML. Inspect the headers riding along.',
      hash: 'f9d7871933331d04d4036eaff417bf9a7c93c2a5a837b9b6122843a10df8e9b1'
    },
    {
      id: 7, slug: 'cookie-room', name: 'Cookie Tampering',
      difficulty: 3, points: 200, path: 'cookie-room.html',
      desc: 'Trust nothing the client holds. Change a cookie, change your privilege.',
      hash: '57f3b7ab6a68af8499c19a093a2bda96b2ff188cca2548a9558778d8867f008f'
    },
    {
      id: 8, slug: 'api-door', name: 'Hidden API',
      difficulty: 3, points: 200, path: 'api-door.html',
      desc: 'The page is quiet, but the network is chatty. Find the endpoint.',
      hash: 'f68173cf803ceea6e162ed26eed29e89036523f911170bda9fd109d5e1f3e3ec'
    },
    {
      id: 9, slug: 'login-gate', name: 'Client-side Login Bypass',
      difficulty: 4, points: 250, path: 'login-gate.html',
      desc: 'Authentication should never live only in the browser. Prove why.',
      hash: 'b67ccc7a536c1c3d636d581fa5b666e40ada7d18ce65b5f2c66adeee88dd0420'
    },
    {
      id: 10, slug: 'final-gate', name: 'Fragment Reassembly',
      difficulty: 4, points: 300, path: 'final-gate.html',
      desc: 'The flag has been shattered across every layer of the page. Hunt every fragment, assemble the truth.',
      hash: '3b44afe5dac472c10081a2e507640ac454ed181feb8c337b9f18823b1d70ffd2'
    }
  ],

  STORAGE_KEY: 'pathhunt_ctf_progress_v1'
};

/* ------------------------------------------------
   SHA-256 helper (WebCrypto)
------------------------------------------------ */
async function sha256(text) {
  const buf = new TextEncoder().encode(text.trim());
  const hashBuf = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hashBuf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/* ------------------------------------------------
   Progress helpers
   `solved` stores SHA-256 HASHES, never plaintext.
------------------------------------------------ */
function getProgress() {
  try {
    const raw = localStorage.getItem(PATHHUNT.STORAGE_KEY);
    if (!raw) return { solved: [], score: 0 };
    const parsed = JSON.parse(raw);
    return {
      solved: Array.isArray(parsed.solved) ? parsed.solved : [],
      score: typeof parsed.score === 'number' ? parsed.score : 0
    };
  } catch (e) {
    return { solved: [], score: 0 };
  }
}

function saveProgress(progress) {
  try {
    localStorage.setItem(PATHHUNT.STORAGE_KEY, JSON.stringify(progress));
  } catch (e) {
    console.error('Failed to save progress', e);
  }
}

// Returns the matching challenge for a plaintext flag, or null if invalid.
// Async because it hashes the input.
async function verifyFlag(plaintext) {
  const hash = await sha256(plaintext);
  const match = PATHHUNT.challenges.find(c => c.hash === hash);
  return match ? { challenge: match, hash } : null;
}

// Mark a challenge solved by its hash. Idempotent.
function markSolvedByHash(hash) {
  const progress = getProgress();
  if (progress.solved.includes(hash)) return { already: true, progress };

  progress.solved.push(hash);

  const ch = PATHHUNT.challenges.find(c => c.hash === hash);
  if (ch) progress.score += ch.points;

  saveProgress(progress);
  return { already: false, progress };
}

// Convenience: is this challenge solved?
function isChallengeSolved(challenge) {
  return getProgress().solved.includes(challenge.hash);
}

function resetProgress() {
  if (!confirm('Reset all progress? This clears solved flags and your score.')) return;
  localStorage.removeItem(PATHHUNT.STORAGE_KEY);
  showToast('Progress reset. Good hunting, agent.', 'success');
  setTimeout(() => window.location.reload(), 600);
}

/* ------------------------------------------------
   UI helpers
------------------------------------------------ */
function showToast(message, type = '') {
  let toast = document.querySelector('.toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.className = 'toast';
    document.body.appendChild(toast);
  }
  toast.textContent = message;
  toast.className = 'toast ' + (type || '');
  void toast.offsetWidth;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 3000);
}

/* ------------------------------------------------
   Navigation injection
------------------------------------------------ */
function renderNav() {
  const host = document.querySelector('[data-nav]');
  if (!host) return;
  const currentPath = window.location.pathname;
  const activeDash = currentPath.endsWith('dashboard.html') ? 'active' : '';
  const activeSubmit = currentPath.endsWith('submit.html') ? 'active' : '';

  host.innerHTML = `
    <nav class="nav">
      <div class="nav-inner">
        <a href="${_base}index.html" class="logo">
          <span class="logo-mark">&gt;_</span>
          <span class="logo-text">PathHunt<span class="accent">_</span>CTF</span>
        </a>
        <ul class="nav-links">
          <li><a href="${_base}dashboard.html" class="${activeDash}">Dashboard</a></li>
          <li><a href="${_base}submit.html" class="${activeSubmit}">Submit Flag</a></li>
          <li><button class="btn-reset" onclick="resetProgress()">Reset</button></li>
        </ul>
      </div>
    </nav>
  `;
}

/* ------------------------------------------------
   Flag reveal helper (used on challenge pages)
------------------------------------------------ */
function revealFlag(flag, nextPath) {
  const el = document.querySelector('[data-flag-reveal]');
  if (!el) return;
  el.querySelector('.flag-text').textContent = flag;
  const nextWrap = el.querySelector('.next-path');
  if (nextPath && nextWrap) {
    nextWrap.innerHTML = `Next path: <a href="${nextPath}">${nextPath}</a>`;
  }
  el.classList.add('show');
}

/* ------------------------------------------------
   Card cursor glow effect
------------------------------------------------ */
function initCardGlow() {
  document.querySelectorAll('.explain-card').forEach(card => {
    card.addEventListener('mousemove', (e) => {
      const rect = card.getBoundingClientRect();
      const x = ((e.clientX - rect.left) / rect.width) * 100;
      const y = ((e.clientY - rect.top) / rect.height) * 100;
      card.style.setProperty('--mx', x + '%');
      card.style.setProperty('--my', y + '%');
    });
  });
}

/* ------------------------------------------------
   Migrate legacy plaintext progress (one-time)
   Earlier builds stored flags as plaintext in
   localStorage. If we detect that, hash them and
   rewrite so nothing plaintext lingers.
------------------------------------------------ */
(async function migrateLegacyProgress() {
  try {
    const raw = localStorage.getItem(PATHHUNT.STORAGE_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed.solved)) return;

    const looksLikePlaintext = parsed.solved.some(
      s => typeof s === 'string' && s.startsWith('flag{')
    );
    if (!looksLikePlaintext) return;

    const migrated = [];
    for (const s of parsed.solved) {
      if (typeof s === 'string' && s.startsWith('flag{')) {
        migrated.push(await sha256(s));
      } else if (typeof s === 'string' && /^[a-f0-9]{64}$/.test(s)) {
        migrated.push(s);
      }
    }
    saveProgress({ solved: migrated, score: parsed.score || 0 });
  } catch (e) {
    // ignore; worst case user re-submits a flag
  }
})();

/* ------------------------------------------------
   Init
------------------------------------------------ */
document.addEventListener('DOMContentLoaded', () => {
  renderNav();
  initCardGlow();
});
