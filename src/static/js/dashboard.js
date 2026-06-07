const liveFeedElement = document.getElementById('live-feed');
const refreshButton = document.getElementById('refresh-button');
const fallbackNotice = document.getElementById('live-feed-fallback');
const statsValues = document.querySelectorAll('.metric-value');

async function fetchLiveFeed() {
    if (!liveFeedElement) {
        return;
    }

    try {
        const response = await fetch('/dashboard/api/live-feed?limit=12', { credentials: 'include' });
        if (!response.ok) {
            throw new Error('Failed to fetch live feed');
        }

        const payload = await response.json();
        renderLiveItems(payload.items || []);
    } catch (error) {
        renderLiveFallback(error.message);
    }
}

function renderLiveItems(items) {
    if (!liveFeedElement) {
        return;
    }

    if (!items.length) {
        liveFeedElement.innerHTML = '<div class="feed-item"><div class="message">Aucune activité récente.</div></div>';
        return;
    }

    liveFeedElement.innerHTML = items.map(item => {
        const time = item.timestamp || item.time || 'n/a';
        const text = item.description || item.event || item.message || 'Événement inconnu';
        return `
            <div class="feed-item">
                <div class="meta">${time}</div>
                <div class="message">${text}</div>
            </div>
        `;
    }).join('');
}

function renderLiveFallback(message) {
    if (!liveFeedElement) {
        return;
    }
    liveFeedElement.innerHTML = `<div class="feed-item"><div class="message">${message}</div></div>`;
}

async function refreshStats() {
    try {
        const response = await fetch('/dashboard/api/stats', { credentials: 'include' });
        if (!response.ok) return;
        const data = await response.json();
        const stats = [
            data.active_sessions,
            data.unique_attackers,
            data.high_threat_count,
            data.ioc_count
        ];
        statsValues.forEach((el, i) => {
            if (el && stats[i] !== undefined) {
                el.textContent = stats[i];
                el.style.transition = 'color 0.3s ease';
                el.style.color = '#0f0';
                setTimeout(() => el.style.color = '', 300);
            }
        });
    } catch (error) {
        console.warn('Stats refresh failed:', error);
    }
}

function connectLiveSocket() {
    if (!liveFeedElement || !window.WebSocket) {
        return;
    }

    const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${scheme}//${location.host}/dashboard/ws/live`);

    ws.addEventListener('open', () => {
        ws.send('ping');
        if (fallbackNotice) {
            fallbackNotice.textContent = 'Flux temps réel connecté.';
        }
    });

    ws.addEventListener('message', event => {
        try {
            const data = JSON.parse(event.data);
            if (data.type === 'pong') {
                return;
            }
        } catch (error) {
            console.warn('WebSocket data parse error', error);
        }
    });

    ws.addEventListener('close', () => {
        if (fallbackNotice) {
            fallbackNotice.textContent = 'Connexion temps réel interrompue, passage au rafraîchissement périodique.';
        }
        window.setTimeout(fetchLiveFeed, 2000);
    });

    ws.addEventListener('error', () => {
        if (fallbackNotice) {
            fallbackNotice.textContent = 'Impossible d’établir le WebSocket. Le flux est toujours disponible via HTTP.';
        }
    });
}

if (refreshButton) {
    refreshButton.addEventListener('click', event => {
        event.preventDefault();
        fetchLiveFeed();
        refreshStats();
    });
}

fetchLiveFeed();
connectLiveSocket();
refreshStats();
setInterval(() => {
    fetchLiveFeed();
    refreshStats();
}, 12000);
