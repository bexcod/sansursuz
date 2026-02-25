// Sansürsüz Web UI — Frontend Logic

const API = '';

let state = {
    active: false,
    dns: 'cloudflare',
    mode: 'selective',
    port: 8443
};

document.addEventListener('DOMContentLoaded', () => {
    fetchStatus();
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
