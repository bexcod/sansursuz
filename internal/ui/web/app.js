// Sansürsüz Web UI — Frontend Logic

const API = '';

let state = {
    active: false,
    dns: 'cloudflare',
    mode: 'selective',
    port: 8443,
    domains: []
};

let domainsExpanded = false;

document.addEventListener('DOMContentLoaded', () => {
    fetchStatus();
    fetchDomains();
    setInterval(fetchStatus, 3000);
});

async function fetchStatus() {
    try {
        const res = await fetch(`${API}/api/status`);
        const data = await res.json();
        state = { ...state, ...data };
        updateUI();
    } catch (e) {
        setStatus(false, 'Bağlantı kesildi');
    }
}

async function fetchDomains() {
    try {
        const res = await fetch(`${API}/api/domains`);
        const data = await res.json();
        state.domains = data.domains || [];
        renderDomains();
    } catch (e) {
        console.error('Domains fetch error:', e);
    }
}

async function togglePower() {
    const btn = document.getElementById('powerBtn');
    btn.style.pointerEvents = 'none';

    try {
        const res = await fetch(`${API}/api/toggle`, { method: 'POST' });
        const data = await res.json();
        state.active = data.active;
        updateUI();
    } catch (e) {
        console.error('Toggle error:', e);
    }

    setTimeout(() => { btn.style.pointerEvents = 'auto'; }, 500);
}

async function updateSetting(key, value) {
    try {
        await fetch(`${API}/api/settings`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ [key]: value })
        });
        state[key] = value;
        updateUI();
    } catch (e) {
        console.error('Settings error:', e);
    }
}

function setMode(mode) {
    updateSetting('mode', mode);
}

function toggleDomains() {
    domainsExpanded = !domainsExpanded;
    const content = document.getElementById('domainsContent');
    const arrow = document.getElementById('expandArrow');

    content.classList.toggle('expanded', domainsExpanded);
    arrow.classList.toggle('expanded', domainsExpanded);
}

async function addDomain() {
    const input = document.getElementById('domainInput');
    const domain = input.value.trim().toLowerCase();
    if (!domain || !domain.includes('.')) return;

    try {
        await fetch(`${API}/api/domains`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'add', domain: domain })
        });
        input.value = '';
        fetchDomains();
    } catch (e) {
        console.error('Add domain error:', e);
    }
}

async function removeDomain(domain) {
    try {
        await fetch(`${API}/api/domains`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'remove', domain: domain })
        });
        fetchDomains();
    } catch (e) {
        console.error('Remove domain error:', e);
    }
}

function renderDomains() {
    const list = document.getElementById('domainList');
    const count = document.getElementById('domainCount');
    const domainCount = state.domains ? state.domains.length : 0;
    count.textContent = domainCount;

    if (!state.domains || domainCount === 0) {
        list.innerHTML = '';
        return;
    }
    list.innerHTML = state.domains.map(d =>
        `<div class="domain-item">
            <span>${d}</span>
            <button class="domain-remove" onclick="removeDomain('${d}')" title="Kaldır">✕</button>
        </div>`
    ).join('');
}

async function quitApp() {
    if (!confirm('Sansürsüz uygulamasını kapatmak istediğinize emin misiniz?')) return;
    try {
        await fetch(`${API}/api/quit`, { method: 'POST' });
    } catch (e) {
        // Expected — server shuts down
    }
    document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;color:#888;font-family:Inter,sans-serif"><p>Uygulama kapatıldı. Bu sekmeyi kapatabilirsiniz.</p></div>';
}

function updateUI() {
    const powerBtn = document.getElementById('powerBtn');
    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');
    const infoText = document.getElementById('infoText');

    if (state.active) {
        powerBtn.classList.add('active');
        statusDot.className = 'status-dot active';
        statusText.textContent = 'Bağlı';
    } else {
        powerBtn.classList.remove('active');
        statusDot.className = 'status-dot inactive';
        statusText.textContent = 'Devre Dışı';
    }

    document.getElementById('dnsSelect').value = state.dns;
    document.getElementById('modeSelective').classList.toggle('active', state.mode === 'selective');
    document.getElementById('modeAll').classList.toggle('active', state.mode === 'all');
    document.getElementById('portInput').value = state.port;

    if (state.active) {
        infoText.textContent = `✅ Tüm sistem aktif — Port ${state.port}`;
    } else {
        infoText.textContent = `Proxy: 127.0.0.1:${state.port}`;
    }
}

function setStatus(active, text) {
    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');
    statusDot.className = active ? 'status-dot active' : 'status-dot inactive';
    statusText.textContent = text;
}
