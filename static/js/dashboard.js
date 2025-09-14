// static/js/dashboard.js
// Externalized script for Kali Data Dashboard
// - persistent unreadIds in localStorage
// - 'Mark all as read' button
// - new intercepted rows stay red until clicked
// - modal view / open in window
// - polling to /api/network-traffic/latest

(function () {
  'use strict';

  const POLL_MS = 5000;
  const STORAGE_KEY = 'kali_unread_ids';

  let lastSeenId = null;   // baseline set on first fetch; don't mark server-rendered rows as unread
  let clickedId = null;
  let updateInterval = null;
  const unreadIds = new Set();

  // ---------- localStorage helpers ----------
  function saveUnreadToStorage() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(Array.from(unreadIds)));
    } catch (e) {
      console.warn('Failed to save unread IDs:', e);
    }
  }
  function loadUnreadFromStorage() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const arr = JSON.parse(raw);
      if (Array.isArray(arr)) arr.forEach(id => unreadIds.add(String(id)));
    } catch (e) {
      console.warn('Failed to load unread IDs:', e);
    }
  }
  function clearStorageIfEmpty() {
    if (unreadIds.size === 0) localStorage.removeItem(STORAGE_KEY);
  }

  // ---------- small utilities ----------
  function base64ToUtf8(b64) {
    try {
      const binary = atob(b64);
      const len = binary.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
      const decoder = new TextDecoder('utf-8', { fatal: false });
      return decoder.decode(bytes);
    } catch (e) {
      return b64;
    }
  }
  function escHtml(s) {
    return String(s).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
  }

  // ---------- modal / window ----------
  function showModalWithContent(contentB64) {
    const modal = document.getElementById('packetModal');
    const cnt = document.getElementById('modal-content');
    let decoded = contentB64;
    if (typeof contentB64 === 'string' && /^[A-Za-z0-9+\/=\s]+$/.test(contentB64) && (contentB64.length % 4 === 0)) {
      decoded = base64ToUtf8(contentB64);
    }
    cnt.textContent = decoded;
    if (modal) modal.style.display = 'block';
  }
  function openContentInWindow(contentB64) {
    const decoded = (typeof contentB64 === 'string') ? ((contentB64.length % 4 === 0) ? base64ToUtf8(contentB64) : contentB64) : String(contentB64);
    const w = window.open('', '_blank');
    if (!w) { showModalWithContent(contentB64); return; }
    const contentHtml = `<pre style="white-space:pre-wrap;font-family:monospace;">${escHtml(decoded)}</pre>`;
    w.document.open();
    w.document.write(`<html><head><title>Packet Content</title></head><body>${contentHtml}</body></html>`);
    w.document.close();
  }

  // ---------- banner / beep ----------
  const bannerEl = document.getElementById('new-banner');
  function showNewBanner(timeout = 6000) {
    if (!bannerEl) return;
    bannerEl.style.display = 'block';
    bannerEl.onclick = () => { bannerEl.style.display = 'none'; };
    clearTimeout(bannerEl._hideTimer);
    bannerEl._hideTimer = setTimeout(() => { bannerEl.style.display = 'none'; }, timeout);
  }
  function playLoudBeep(duration = 260, frequency = 1200, volume = 0.25) {
    try {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      const ctx = new AudioContext();
      const o = ctx.createOscillator();
      const g = ctx.createGain();
      o.type = 'sine';
      o.frequency.value = frequency;
      g.gain.value = volume;
      o.connect(g);
      g.connect(ctx.destination);
      o.start();
      setTimeout(() => {
        o.stop();
        setTimeout(() => ctx.close(), 80);
      }, duration);
    } catch (e) {
      console.warn('Beep failed:', e);
    }
  }

  // ---------- styling based on unread/ clicked ----------
  function styleRowsFromSets() {
    const tbody = document.getElementById('network-traffic-body');
    if (!tbody) return;
    tbody.querySelectorAll('tr').forEach(tr => {
      const id = tr.getAttribute('data-id');
      tr.classList.remove('unread', 'clicked');
      if (id && String(id) === String(clickedId)) {
        tr.classList.add('clicked');
      } else if (id && unreadIds.has(String(id))) {
        tr.classList.add('unread');
      }
    });
  }

  function markAllAsRead() {
    unreadIds.clear();
    saveUnreadToStorage();
    clearStorageIfEmpty();
    styleRowsFromSets();
  }

  // ---------- table management ----------
  function ensureTableExists() {
    const container = document.getElementById('network-traffic-container');
    if (!container) return;
    if (!document.getElementById('network-traffic-body')) {
      container.innerHTML = `
        <table class="data-table" id="network-table">
          <thead>
            <tr><th>Timestamp</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Content (preview)</th><th>Service</th></tr>
          </thead>
          <tbody id="network-traffic-body"></tbody>
        </table>`;
    }
  }

  function updateTable(data) {
    ensureTableExists();
    const container = document.getElementById('network-traffic-container');
    if (!data || data.length === 0) {
      container.innerHTML = `<div class="no-data"><h2>No network traffic data available</h2><p>Wait for data from your Kali machine.</p></div>`;
      return;
    }

    const tbody = document.getElementById('network-traffic-body');
    tbody.innerHTML = '';

    data.forEach(item => {
      const tr = document.createElement('tr');
      if (item.id !== undefined && item.id !== null) tr.setAttribute('data-id', item.id);

      // timestamp
      const tdTime = document.createElement('td');
      tdTime.textContent = (typeof item.timestamp === 'string') ? item.timestamp : (item.timestamp ? new Date(item.timestamp).toLocaleString() : '');
      tr.appendChild(tdTime);

      // source / dest / proto
      const tdSource = document.createElement('td'); tdSource.textContent = item.source || ''; tr.appendChild(tdSource);
      const tdDest = document.createElement('td'); tdDest.textContent = item.dest || ''; tr.appendChild(tdDest);
      const tdProto = document.createElement('td'); tdProto.textContent = item.protocol || ''; tr.appendChild(tdProto);

      // content preview
      const tdContent = document.createElement('td'); tdContent.className = 'content-cell';
      if (item.content) {
        let contentStr = (typeof item.content === 'string') ? item.content : JSON.stringify(item.content);
        let previewText = contentStr;
        if (typeof contentStr === 'string' && contentStr.length % 4 === 0 && /^[A-Za-z0-9+\/=\s]+$/.test(contentStr)) {
          try { previewText = base64ToUtf8(contentStr).substring(0, 100); } catch (e) { previewText = contentStr.substring(0, 100); }
        } else {
          previewText = contentStr.substring(0, 100);
        }

        if (contentStr.length > 100) {
          const preview = document.createElement('span'); preview.className = 'preview'; preview.textContent = previewText + '...'; tdContent.appendChild(preview);
          const viewLink = document.createElement('span'); viewLink.className = 'view-content-link'; viewLink.setAttribute('data-content', JSON.stringify(contentStr)); viewLink.textContent = 'View full content'; tdContent.appendChild(viewLink);
          const openLink = document.createElement('span'); openLink.className = 'open-window-link'; openLink.setAttribute('data-content', JSON.stringify(contentStr)); openLink.textContent = 'Open in window'; tdContent.appendChild(openLink);
        } else {
          const preview = document.createElement('span'); preview.className = 'preview'; preview.textContent = previewText; tdContent.appendChild(preview);
          const openLink = document.createElement('span'); openLink.className = 'open-window-link'; openLink.setAttribute('data-content', JSON.stringify(contentStr)); openLink.textContent = 'Open in window'; tdContent.appendChild(openLink);
        }
      } else {
        tdContent.textContent = 'No content';
      }
      tr.appendChild(tdContent);

      // service
      const tdService = document.createElement('td'); tdService.textContent = item.service || ''; tr.appendChild(tdService);

      tbody.appendChild(tr);
    });

    // Decide newly arrived rows compared to prev lastSeenId
    const prevLast = lastSeenId;
    const first = data[0];
    const firstId = first && first.id ? String(first.id) : null;

    if (prevLast !== null && firstId !== null && firstId !== String(prevLast)) {
      // We will mark rows as unread until we encounter prevLast.
      for (const item of data) {
        if (item.id === undefined || item.id === null) continue;
        const sid = String(item.id);
        if (sid === String(prevLast)) break;
        // mark as unread (persist)
        unreadIds.add(sid);
      }
      saveUnreadToStorage();
      clearStorageIfEmpty();
      showNewBanner();
      playLoudBeep();
    }

    // On initial load, set baseline (don't mark server-rendered rows unread)
    if (lastSeenId === null && firstId !== null) {
      lastSeenId = firstId;
    }

    styleRowsFromSets();

    if (firstId !== null) lastSeenId = firstId;
  }

  // ---------- polling ----------
  function fetchLatestData() {
    fetch('/api/network-traffic/latest')
      .then(resp => resp.json())
      .then(data => updateTable(data))
      .catch(err => console.error('fetch error', err));
  }
  function startAutoUpdate() { if (updateInterval) clearInterval(updateInterval); updateInterval = setInterval(fetchLatestData, POLL_MS); }
  function stopAutoUpdate() { if (updateInterval) clearInterval(updateInterval); updateInterval = null; }

  // ---------- event delegation for links ----------
  document.addEventListener('click', function (e) {
    const el = e.target;
    if (!el) return;

    if (el.classList && el.classList.contains('view-content-link')) {
      const raw = el.getAttribute('data-content');
      let content = raw;
      try { content = JSON.parse(raw); } catch (e) {}
      const tr = el.closest('tr');
      if (tr) {
        clickedId = tr.getAttribute('data-id');
        if (clickedId) {
          unreadIds.delete(String(clickedId));
          saveUnreadToStorage();
          clearStorageIfEmpty();
        }
        styleRowsFromSets();
      }
      // decode and show
      let decoded = content;
      if (typeof content === 'string' && content.length % 4 === 0 && /^[A-Za-z0-9+\/=\s]+$/.test(content)) {
        decoded = base64ToUtf8(content);
      }
      showModalWithContent(decoded);
    }

    if (el.classList && el.classList.contains('open-window-link')) {
      const raw = el.getAttribute('data-content');
      let content = raw;
      try { content = JSON.parse(raw); } catch (e) {}
      const tr = el.closest('tr');
      if (tr) {
        clickedId = tr.getAttribute('data-id');
        if (clickedId) {
          unreadIds.delete(String(clickedId));
          saveUnreadToStorage();
          clearStorageIfEmpty();
        }
        styleRowsFromSets();
      }
      if (typeof content === 'string' && content.length % 4 === 0 && /^[A-Za-z0-9+\/=\s]+$/.test(content)) {
        openContentInWindow(base64ToUtf8(content));
      } else {
        openContentInWindow(String(content));
      }
    }
  });

  // modal close
  document.addEventListener('click', function(ev) {
    const modal = document.getElementById('packetModal');
    if (!modal) return;
    if (ev.target === modal) modal.style.display = 'none';
  });
  const modalClose = document.getElementById('modal-close');
  if (modalClose) modalClose.addEventListener('click', () => {
    const modal = document.getElementById('packetModal');
    if (modal) modal.style.display = 'none';
  });

  // ---------- Mark all as read button (create if not present in template) ----------
  function ensureMarkAllButton() {
    let markBtn = document.getElementById('mark-read-btn');
    if (!markBtn) {
      const container = document.querySelector('.action-buttons');
      if (container) {
        markBtn = document.createElement('button');
        markBtn.id = 'mark-read-btn';
        markBtn.className = 'btn';
        markBtn.style.marginLeft = '10px';
        markBtn.textContent = 'Mark all as read';
        container.appendChild(markBtn);
      }
    }
    if (markBtn) {
      markBtn.addEventListener('click', () => markAllAsRead());
    }
  }

  // ---------- toggle auto-update / refresh wiring ----------
  function wireControls() {
    const toggleBtn = document.getElementById('toggle-update');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', function() {
        const indicator = document.getElementById('update-indicator');
        const status = document.getElementById('update-status');
        const btn = toggleBtn;
        if (updateInterval) {
          // paused -> resume
          stopAutoUpdate();
          indicator.className = 'update-indicator paused';
          status.textContent = 'Auto-update paused';
          btn.textContent = 'Resume Updates';
        } else {
          startAutoUpdate();
          indicator.className = 'update-indicator updating';
          status.textContent = 'Auto-update enabled (updates every 5 seconds)';
          btn.textContent = 'Pause Updates';
        }
      });
    }

    const refreshBtn = document.getElementById('refresh-btn');
    if (refreshBtn) refreshBtn.addEventListener('click', fetchLatestData);
  }

  // ---------- initialization ----------
  function init() {
    // load persisted unread set
    loadUnreadFromStorage();

    // If the template rendered rows server-side, use the top row as baseline (don't mark them unread)
    const firstRow = document.querySelector('#network-traffic-body tr');
    if (firstRow) {
      const fid = firstRow.getAttribute('data-id');
      if (fid) lastSeenId = String(fid);
    }

    // style server-rendered rows according to unreadIds (if any)
    styleRowsFromSets();

    // wire controls and mark all
    wireControls();
    ensureMarkAllButton();

    // start polling
    startAutoUpdate();
    fetchLatestData();
  }

  // run on DOMContentLoaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
