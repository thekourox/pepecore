const $ = id => document.getElementById(id);
let SERVERS = [], STATE = null, logTimer = null;

function toast(msg, bad) {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast show' + (bad ? ' bad' : '');
  setTimeout(() => t.className = 'toast', 4000);
}

async function api(path, method = 'GET', body = null, panelAuth = false) {
  const opt = { method, headers: { 'Content-Type': 'application/json' } };
  
  const token = localStorage.getItem('pepe_token');
  if (token) opt.headers['Authorization'] = 'Bearer ' + token;

  if (panelAuth) {
    const h = $('pHost').value.trim(), t = $('pToken').value.trim();
    if (!h || !t) throw new Error('Enter the panel URL and token first');
    opt.headers['X-Panel-Host'] = h;
    // Overwrite Authorization if panelAuth is true, as per original logic? 
    // Wait, original logic sent the panel token in Authorization header.
    // We now have our own Authorization header. Let's send the panel token as X-Panel-Token.
    // Actually, backend app.py still reads `authorization` from Header for panel API.
    // This is a conflict! Let's just pass panel token in X-Panel-Token instead in frontend, and update backend?
    // OR we can pass it as Authorization and the auth_middleware will just pass it through because it doesn't check /api/panel/?
    // Wait, auth_middleware DOES check /api/panel/.
    opt.headers['X-Panel-Token'] = t;
  }
  if (body) opt.body = JSON.stringify(body);
  const r = await fetch(path, opt);
  if (r.status === 401 && !path.startsWith('/api/auth/')) {
      showLogin();
      throw new Error("Authentication required");
  }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || r.statusText);
  return data;
}

function showLogin() {
  $('loginOverlay').style.display = 'flex';
  const btn = $('btnLogout');
  if (btn) btn.style.display = 'none';
}

async function doLogin() {
  const u = $('lUser').value.trim();
  const p = $('lPass').value.trim();
  if (!u || !p) return toast('Enter username and password', true);
  try {
    const r = await fetch('/api/auth/login', {
      method: 'POST', 
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: u, password: p})
    });
    if (!r.ok) throw new Error("Invalid username or password");
    const d = await r.json();
    localStorage.setItem('pepe_token', d.token);
    $('loginOverlay').style.display = 'none';
    const btn = $('btnLogout');
    if (btn) btn.style.display = 'block';
    
    // Once logged in, we must call checkAuthOnLoad so everything initializes properly
    checkAuthOnLoad();
  } catch (e) { toast(e.message, true); }
}

async function doLogout() {
  await fetch('/api/auth/logout', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + localStorage.getItem('pepe_token') }
  });
  localStorage.removeItem('pepe_token');
  showLogin();
}

async function checkAuthOnLoad() {
  try {
    const r = await api('/api/auth/me');
    $('loginOverlay').style.display = 'none';
    if (!r.setup_required) {
       const btn = $('btnLogout');
       if (btn) btn.style.display = 'block';
    }
    refresh();
  } catch (e) {
     // showLogin handled by api()
  }
}

async function act(path, method, body) {
  try {
    const d = await api(path, method, body);
    toast(d.note || d.message || 'Done');
    refresh();
  } catch (e) { toast(e.message, true); }
}

// ---------- tabs ----------
document.querySelectorAll('.tab').forEach(t => t.onclick = () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('.view').forEach(x => x.classList.remove('active'));
  t.classList.add('active');
  $('view-' + t.dataset.view).classList.add('active');
  if (t.dataset.view === 'logs') loadLogs();
  if (t.dataset.view === 'slots') loadServers();
  if (t.dataset.view === 'ports') loadPorts();
  if (t.dataset.view === 'keys') loadKeyHealth();
});

// ---------- refresh ----------
async function refresh(deep) {
  try {
    const d = await api('/api/engine/status' + (deep ? '?deep=true' : ''));
    STATE = d;
    $('sTotal').textContent = d.total;
    $('sAlive').textContent = d.alive;
    $('sDead').textContent  = d.dead;
    $('sEmpty').textContent = d.empty;

    $('bindState').textContent = d.binding.bound
      ? 'bound \u00b7 core ' + d.binding.core_id + ' \u00b7 ' + d.binding.slot_count + ' slots'
      : 'not bound yet';
    $('bindState').className = 'bind-state ' + (d.binding.bound ? 'ok' : 'warn');

    const w = d.watchdog;
    const displaced = w.displaced
      ? '<p class="hint warn">' + w.displaced + ' slot(s) are temporarily exiting from a ' +
        'neighbouring country because their own is unreachable. They will be moved back ' +
        'automatically once it recovers.</p>' : '';
    $('wdBox').innerHTML = '<h3>Watchdog</h3><div class="kv">' +
      '<span>Cycles</span><b>' + w.cycles + '</b>' +
      '<span>Servers swapped</span><b>' + w.swaps + '</b>' +
      '<span>Brought home</span><b>' + (w.repatriated || 0) + '</b>' +
      '<span>Displaced now</span><b>' + (w.displaced || 0) + '</b>' +
      '<span>Restarts</span><b>' + w.restarts + '</b>' +
      '<span>Last run</span><b>' + (w.last_run || '-') + '</b></div>' + displaced +
      '<p class="hint">Failovers happen silently. The panel is never notified, because ' +
      'nothing it knows about has changed.</p>';

    markSteps(d);
    renderKeys(d.identities);
    renderSlots();
  } catch (e) { toast(e.message, true); }
}

function markSteps(d) {
  const done = [
    d.identities.length > 0,
    d.total > 0,
    d.total - d.empty > 0,
    d.binding.bound
  ];
  done.forEach((ok, i) => {
    const step = $('step' + (i + 1));
    const mark = $('mark' + (i + 1));
    if (!step) return;
    step.classList.toggle('done', ok);
    mark.textContent = ok ? '\u2713' : '';
  });
  if (d.binding.bound) $('panelOps').style.display = 'flex';
}

// ---------- keys ----------
function renderKeys(items) {
  if (!items.length) {
    $('keyList').innerHTML = '<p class="hint">No keys yet — add one in step 1.</p>';
    return;
  }
  $('keyList').innerHTML = items.map(i =>
    '<div class="item">' +
      '<div><b>' + i.label + '</b> <code>' + i.id + '</code>' +
        '<div class="sub">' + i.key_preview + ' \u00b7 ' + i.address + '</div></div>' +
      '<div class="acts">' +
        '<input class="mini" id="rot-' + i.id + '" placeholder="new private key">' +
        '<button class="btn sm" onclick="rotate(\'' + i.id + '\',\'' + i.address + '\')">Rotate</button>' +
        '<button class="btn sm danger ghost" onclick="delKey(\'' + i.id + '\')">\u00d7</button>' +
      '</div></div>').join('');
}

async function addKey(second) {
  const key = (second ? $('kNew2') : $('kNew')).value.trim();
  if (!key) return toast('Enter a private key', true);
  const addr = (second ? $('kAddr2') : $('kAddr')).value.trim();
  const label = (second ? $('kLabel2') : $('kLabel')).value.trim();
  try {
    await api('/api/engine/identities', 'POST',
      { private_key: key, address: addr, label: label });
    (second ? $('kNew2') : $('kNew')).value = '';
    toast('Key added');
    refresh(); loadKeyHealth();
  } catch (e) { toast(e.message, true); }
}

async function rotate(id, addr) {
  const key = $('rot-' + id).value.trim();
  if (!key) return toast('Enter the new private key', true);
  if (!confirm('Rotate this key?\n\nAffected tunnels restart on the SAME ports.\n' +
               'The panel is not contacted and user configs stay valid.')) return;
  try {
    const d = await api('/api/engine/identities/' + id, 'PUT',
      { private_key: key, address: addr });
    toast('Rotated across ' + d.slots_affected.length + ' slots \u2014 panel untouched');
    refresh();
  } catch (e) { toast(e.message, true); }
}

async function delKey(id) {
  if (!confirm('Delete this key? Slots using it will stop until reassigned.')) return;
  await act('/api/engine/identities/' + id, 'DELETE');
}

// ---------- capacity ----------
async function checkCapacity() {
  try {
    const r = await api('/api/engine/capacity?target=' + (+$('capSlots').value || 0));
    let h = '<div class="kv">' +
      '<span>Target slots</span><b>' + r.target_slots + '</b>' +
      '<span>Keys present / needed</span><b>' + r.keys_present + ' / ' + r.keys_needed + '</b>';
    if (r.ram_total_mb) h += '<span>RAM needed / total</span><b>~' + r.ram_estimate_mb +
      ' MB / ' + r.ram_total_mb + ' MB</b>';
    if (r.fd_limit) h += '<span>Open files needed / limit</span><b>~' + r.fd_estimate +
      ' / ' + r.fd_limit + '</b>';
    h += '<span>Boot time</span><b>~' + r.boot_seconds_estimate + 's</b></div>';

    r.blockers.forEach(b => { h += '<div class="banner bad">' + b + '</div>'; });
    r.warnings.forEach(w => { h += '<p class="hint warn">' + w + '</p>'; });
    if (r.ok && !r.warnings.length)
      h += '<div class="banner ok">This size looks workable on this machine.</div>';
    $('capInfo').innerHTML = h;
  } catch (e) { toast(e.message, true); }
}

async function importKeys() {
  const blob = $('kBlob').value.trim();
  if (!blob) return toast('Paste some keys first', true);
  try {
    const d = await api('/api/engine/identities/bulk', 'POST', {
      blob: blob, default_address: $('kBlobAddr').value.trim()
    });
    $('kBlob').value = '';
    toast('Imported ' + d.added_count + ' keys' +
      (d.skipped_duplicates ? ' (' + d.skipped_duplicates + ' duplicates skipped)' : '') +
      ' \u2014 total ' + d.total_keys);
    loadKeyHealth(); refresh();
  } catch (e) { toast(e.message, true); }
}

// ---------- key health & rotation ----------
async function loadKeyHealth() {
  try {
    const kl = await api('/api/engine/keyload');
    const rot = await api('/api/engine/rotator');
    renderKeyLoad(kl);
    renderRotator(rot);
  } catch (e) { toast(e.message, true); }
}

function renderKeyLoad(kl) {
  const box = $('keyLoad');
  if (!box) return;

  if (!kl.keys_present) {
    box.innerHTML = '<div class="banner warn">No keys added yet.</div>';
    return;
  }

  const over = kl.keys.filter(k => k.overloaded);
  let html = '';

  if (over.length) {
    const worst = Math.max.apply(null, over.map(k => k.slot_count));
    html += '<div class="banner bad">' +
      '<strong>A key is carrying too many tunnels.</strong> ' +
      'One keypair is serving ' + worst + ' servers at once (a safe working ' +
      'limit is around ' + kl.limit_per_key + '). This is the usual cause of ' +
      'locations dropping at random every hour or two and only coming back ' +
      'when you replace the key: the provider sees one identity connected ' +
      'from many places and culls the extra sessions.<br><br>' +
      '<b>Fix:</b> you have ' + kl.keys_present + ' key(s) and want about ' +
      kl.keys_needed + '. Generate more keypairs in your Surfshark account\'s ' +
      'WireGuard section — several keys can live on one account, no extra ' +
      'subscription needed — add them below, then hit ' +
      '&ldquo;Spread keys evenly&rdquo;.</div>';
  } else {
    html += '<div class="banner ok">Key load looks healthy — no keypair is ' +
      'carrying more than ' + kl.limit_per_key + ' tunnels.</div>';
  }

  html += '<div class="kv">' +
    '<span>Live tunnels</span><b>' + kl.total_live_slots + '</b>' +
    '<span>Keys present</span><b>' + kl.keys_present + '</b>' +
    '<span>Keys recommended</span><b>' + kl.keys_needed + '</b>' +
    '<span>Limit per key</span><b>' + kl.limit_per_key + '</b></div>';

  if (kl.orphan_slots.length) {
    html += '<p class="hint warn">Slots with no key assigned: ' +
      kl.orphan_slots.join(', ') + ' — run &ldquo;Spread keys evenly&rdquo;.</p>';
  }

  box.innerHTML = html;
}

function renderRotator(r) {
  const box = $('rotInfo');
  if (!box) return;
  $('rotOn').checked = r.enabled;
  $('rotInterval').value = String(r.interval_hours);

  let note = '';
  if (r.enabled && !r.effective) {
    note = '<p class="hint warn">Rotation is on but there is only one key, ' +
           'so each cycle is a no-op. Add more keypairs first.</p>';
  }
  const last = r.last_result
    ? (r.last_result.skipped
        ? '<span>Last cycle</span><b>' + r.last_result.skipped + '</b>'
        : '<span>Last cycle</span><b>' + r.last_result.rotated + ' slots moved</b>')
    : '';

  box.innerHTML = '<div class="kv">' +
    '<span>Status</span><b>' + (r.enabled ? 'on, every ' + r.interval_hours + 'h' : 'off') + '</b>' +
    '<span>Cycles run</span><b>' + r.cycles + '</b>' +
    '<span>Last run</span><b>' + (r.last_run || '-') + '</b>' +
    '<span>Next run</span><b>' + (r.next_run || '-') + '</b>' +
    last + '</div>' + note;
}

async function saveRotator() {
  try {
    const d = await api('/api/engine/rotator', 'POST', {
      enabled: $('rotOn').checked,
      interval_hours: parseFloat($('rotInterval').value)
    });
    toast(d.enabled
      ? 'Rotation on — every ' + d.interval_hours + 'h'
      : 'Rotation off');
    renderRotator(d);
  } catch (e) { toast(e.message, true); }
}

async function rotateNow() {
  if (!confirm('Rotate keys across all slots now?\n\nTunnels restart on the same ' +
               'ports and countries. Users reconnect within a few seconds.')) return;
  try {
    toast('Rotating...');
    const d = await api('/api/engine/rotator/run', 'POST');
    toast(d.skipped || (d.rotated + ' slots moved across ' + d.keys_in_pool + ' keys'));
    loadKeyHealth(); refresh();
  } catch (e) { toast(e.message, true); }
}

// ---------- slots ----------
async function ensureSlots() {
  await act('/api/engine/slots/ensure', 'POST', { count: +$('slotCount').value });
}

async function autofill() {
  const n = +($('fillCount') ? $('fillCount').value : 0) || 0;
  if (!confirm('Fill empty slots with one country each and pin them?')) return;
  try {
    toast('Filling slots, this takes a moment...');
    const d = await api('/api/engine/slots/autofill', 'POST', { count: n, pin: true });
    toast(d.message || ('Filled and pinned ' + d.filled + ' slots'));
    refresh();
  } catch (e) { toast(e.message, true); }
}

async function loadServers(force) {
  if (SERVERS.length && !force) return renderSlots();
  try {
    SERVERS = await api('/api/engine/surfshark/servers' + (force ? '?force=true' : ''));
    toast(SERVERS.length + ' Surfshark servers loaded');
    renderSlots();
  } catch (e) { toast(e.message, true); }
}

function renderSlots() {
  if (!STATE) return;
  const filter = ($('slotFilter') ? $('slotFilter').value : '').trim().toLowerCase();
  const norm = x => (x || '').replace(/[\s-]/g, '').toLowerCase();

  const rows = STATE.slots.filter(s => {
    if (!filter) return true;
    return ((s.locked_country || '') + (s.country || '')).toLowerCase().includes(filter);
  });

  if (!rows.length) {
    $('slotList').innerHTML = '<p class="hint">No slots match.</p>';
    return;
  }

  const opts = SERVERS.map((s, i) =>
    '<option value="' + i + '">' + s.country +
    (s.location ? ' / ' + s.location : '') + '</option>').join('');

  $('slotList').innerHTML = rows.map(s => {
    const cls = s.status === 'up' ? 'up' : s.status === 'down' ? 'down' : 'idle';
    const pinned = s.locked_country;
    const drift = pinned && s.country && norm(pinned) !== norm(s.country);
    const where = pinned
      ? '\uD83D\uDD12 ' + pinned + (s.location ? ' / ' + s.location : '')
      : (s.country ? s.country + (s.location ? ' / ' + s.location : '') : '\u2014 empty \u2014');
    const driftTag = drift
      ? '<span class="drift">temporarily via ' + s.country + '</span>' : '';

    return '<div class="item ' + cls + '">' +
      '<div><b>Slot ' + String(s.index).padStart(3, '0') + '</b>' +
        '<span class="port">:' + s.port + '</span>' +
        '<span class="badge ' + cls + '">' + s.status + '</span>' + driftTag +
        '<div class="sub">' + where + (s.endpoint ? ' \u00b7 ' + s.endpoint : '') + '</div></div>' +
      '<div class="acts">' +
        '<select class="mini" id="srv-' + s.index + '">' + opts + '</select>' +
        '<button class="btn sm" onclick="pinSlot(' + s.index + ',' + (pinned ? 'true' : 'false') + ')">' +
          (pinned ? 'Move' : 'Pin') + '</button>' +
        '<button class="btn sm ghost" title="restart" onclick="act(\'/api/engine/slots/' +
          s.index + '/restart\',\'POST\')">\u21bb</button>' +
        (s.endpoint ? '<button class="btn sm danger ghost" title="clear" onclick="clearSlot(' +
          s.index + ')">\u00d7</button>' : '') +
      '</div></div>';
  }).join('');
}

async function pinSlot(idx, alreadyPinned) {
  const sel = $('srv-' + idx);
  if (!sel || !SERVERS.length) return toast('Load the server list first', true);
  const s = SERVERS[+sel.value];
  if (!s) return toast('Pick a country', true);

  if (alreadyPinned && !confirm(
      'Move slot ' + idx + ' to ' + s.country + '?\n\n' +
      'Everyone using this slot\'s inbound will start exiting from ' + s.country +
      ', with no change on their side.')) return;

  const path = alreadyPinned
    ? '/api/engine/slots/' + idx + '/relocate'
    : '/api/engine/slots/' + idx + '/pin';
  try {
    await api(path, 'POST', { country: s.country, location: s.location });
    toast('Slot ' + idx + ' pinned to ' + s.country + ' \u2014 port unchanged, panel untouched');
    refresh();
  } catch (e) { toast(e.message, true); }
}

async function clearSlot(idx) {
  if (!confirm('Clear slot ' + idx + '?\n\nThe port stays reserved, so the panel config ' +
               'remains valid. Anyone using this slot loses connectivity until you refill it.')) return;
  await act('/api/engine/slots/' + idx + '/server', 'DELETE');
}

function confirmStop() {
  if (!confirm('Stop every tunnel?\n\nAll users on these slots go offline until you restart.')) return;
  act('/api/engine/stop', 'POST');
}

// ---------- ports ----------
async function loadPorts() {
  try {
    const d = await api('/api/engine/ports');
    $('portInfo').innerHTML = '<div class="kv">' +
      '<span>SOCKS range</span><b>' + d.socks_base + '\u2013' + (d.socks_base + d.max_slots - 1) + '</b>' +
      '<span>Inbound range</span><b>' + d.inbound_base + '\u2013' + (d.inbound_base + d.max_slots - 1) + '</b>' +
      '<span>Max slots</span><b>' + d.max_slots + '</b></div>';
    $('portList').innerHTML = d.slots.length ? d.slots.map(s =>
      '<div class="item"><div><b>Slot ' + String(s.index).padStart(3, '0') + '</b>' +
      '<div class="sub">SOCKS :' + s.socks_port + ' \u00b7 inbound :' + s.inbound_port +
      ' \u00b7 ' + s.inbound_tag + '</div></div>' +
      '<div class="acts"><span class="sub">' + (s.country || '\u2014') + '</span></div></div>').join('')
      : '<p class="hint">No slots reserved yet.</p>';
  } catch (e) { toast(e.message, true); }
}

async function resyncPorts() {
  try {
    const d = await api('/api/engine/ports/resync', 'POST');
    if (!d.slots_corrected) return toast('Ports already match config - nothing to do');
    toast(d.slots_corrected + ' slot(s) corrected. Re-run Bind so the panel follows.');
    loadPorts(); refresh();
  } catch (e) { toast(e.message, true); }
}

// ---------- panel ----------
async function loadPanel() {
  try {
    const cores = await api('/api/panel/cores', 'GET', null, true);
    const hosts = await api('/api/panel/hosts', 'GET', null, true);
    $('pCore').innerHTML = cores.map(c =>
      '<option value="' + c.id + '">' + c.name + '</option>').join('');
    $('pHostSel').innerHTML = hosts.map(h =>
      '<option value="' + h.id + '">' + (h.remark || h.inbound_tag) +
      ' (' + h.inbound_tag + ')</option>').join('');
    $('bindForm').style.display = 'flex';
    if (STATE) $('pSlots').value = STATE.total || 25;
    toast('Panel connected');
  } catch (e) { toast(e.message, true); }
}

async function doBind() {
  if (!confirm('Bind slot ports to the core config?\n\nThis is a one-time setup step. ' +
               'Existing slots keep their UUIDs, so current subscriptions stay valid.')) return;
  try {
    toast('Binding, this can take a minute...');
    const d = await api('/api/panel/bind', 'POST', {
      core_id: $('pCore').value,
      template_host_id: $('pHostSel').value,
      slot_count: +$('pSlots').value,
      node_ip: $('pNodeIp').value.trim()
    }, true);
    toast('Bound ' + d.slots_bound + ' slots (' + d.hosts_created + ' new, ' +
          d.hosts_reused + ' reused)');
    refresh();
  } catch (e) { toast(e.message, true); }
}

async function toggleHosts(enable) {
  try {
    const d = await api('/api/panel/toggle', 'POST', { enable: enable }, true);
    toast(d.updated + ' hosts ' + (enable ? 'enabled' : 'disabled'));
  } catch (e) { toast(e.message, true); }
}

async function doUnbind() {
  if (!confirm('Remove every PepeCore inbound, outbound and host from the panel?\n\n' +
               'Users on these slots lose access immediately. Local tunnels keep running.')) return;
  try {
    const d = await api('/api/panel/bind/' + $('pCore').value, 'DELETE', null, true);
    toast('Removed ' + d.hosts_removed + ' hosts from the panel');
    refresh();
  } catch (e) { toast(e.message, true); }
}

// ---------- logs ----------
async function loadLogs() {
  try {
    const d = await api('/api/engine/logs');
    const box = $('logBox');
    box.textContent = d.logs;
    box.scrollTop = box.scrollHeight;
  } catch (e) { toast(e.message, true); }
}

document.addEventListener('change', e => {
  if (e.target.id === 'autoLog') {
    if (e.target.checked) { logTimer = setInterval(loadLogs, 5000); loadLogs(); }
    else { clearInterval(logTimer); logTimer = null; }
  }
});

checkAuthOnLoad();
setInterval(() => { if (!document.hidden && $('loginOverlay').style.display === 'none') refresh(); }, 20000);
