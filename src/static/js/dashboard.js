// SOC Dashboard - Alpine.js State + SSE + Leaflet
// Resilience Pattern: Auto-reconnect on SSE errors

function dashboardState() {
    return {
        // Reactive state
        stats: {
            total_events: 0,
            attacks_24h: 0,
            unique_ips_24h: 0,
            active_sessions: 0
        },
        events: [],
        selectedSession: null,
        connected: false,
        evtSource: null,
        markers: {},
        map: null,
        filters: ['all', 'ssh_login', 'telnet', 'command', 'attack'],
        activeFilter: 'all',
        
        // Initialize on load
        init() {
            this.loadInitialStats();  // Load from rendered HTML first
            this.loadStats();        // Then fetch fresh data
            setTimeout(() => this.initMap(), 100);  // Wait for Tailwind styles
            this.initSSE();
            this.loadSessions();
        },
        
        // Stats loading
        async loadStats() {
            try {
                const resp = await fetch('/dashboard/stats');
                const data = await resp.json();
                this.stats = { ...this.stats, ...data };
            } catch (e) {
                console.error('Stats load failed:', e);
            }
        },
        
        // Load initial stats from rendered HTML (fallback)
        loadInitialStats() {
            const bodyEl = document.querySelector('body[x-data]');
            const initialStats = bodyEl?.dataset?.initialStats;
            if (initialStats) {
                try {
                    const data = JSON.parse(initialStats);
                    this.stats = { ...this.stats, ...data };
                } catch (e) {
                    console.warn('Initial stats parse failed:', e);
                }
            }
        },
        
        // Leaflet map initialization - called after DOM is ready
        initMap() {
            const mapEl = document.getElementById('map');
            if (!mapEl || mapEl.offsetHeight === 0) {
                setTimeout(() => this.initMap(), 100);
                return;
            }
            
            this.map = L.map('map').setView([20, 0], 2);
            
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                attribution: 'Honeypot SOC',
                className: 'map-tiles'
            }).addTo(this.map);
        },
        
        // Geolocate IP and add marker
        async geolocateIP(ip) {
            if (this.markers[ip]) return;
            
            try {
                const resp = await fetch(`https://ipapi.co/${ip}/json/`);
                const data = await resp.json();
                
                const latlng = [data.lat, data.lon];
                if (latlng[0] && latlng[1]) {
                    const marker = L.marker(latlng).addTo(this.map)
                        .bindPopup(`<b>${ip}</b><br>${data.city || ''}, ${data.country_name || ''}`);
                    this.markers[ip] = marker;
                }
            } catch (e) {
                console.warn('Geolocation failed for:', ip);
            }
        },
        
        // SSE stream with resilience
        initSSE() {
            this.connectSSE();
            
            // Heartbeat ping every 30s
            setInterval(() => this.loadStats(), 30000);
        },
        
        connectSSE() {
            this.evtSource = new EventSource('/dashboard/stream');
            this.connected = true;
            
            this.evtSource.onmessage = (e) => {
                const event = JSON.parse(e.data);
                this.addEventToFeed(event);
            };
            
            this.evtSource.onerror = () => {
                this.connected = false;
                this.evtSource.close();
                
                // Resilience Pattern: Auto-reconnect after 3s
                setTimeout(() => {
                    this.connectSSE();
                }, 3000);
            };
        },
        
        // Add event to live feed
        addEventToFeed(event) {
            // Filter check
            if (this.activeFilter !== 'all' && event.type !== this.activeFilter) {
                return;
            }
            
            // Geolocate IP
            if (event.data?.ip) {
                this.geolocateIP(event.data.ip);
            }
            
            // Add to events list
            this.events.unshift(event);
            this.stats.total_events = (this.stats.total_events || 0) + 1;
            
            // Update DOM
            this.renderEventCard(event);
        },
        
        // Render event card (for HTMX compatibility)
        renderEventCard(event) {
            const eventsDiv = document.getElementById('events');
            const div = document.createElement('div');
            div.className = 'event-card';
            div.innerHTML = `
                <div class="flex items-center justify-between mb-1">
                    <span class="event-type text-xs px-2 py-0.5 bg-blue-400 text-black rounded">${event.type}</span>
                    <span class="event-time text-xs text-gray-600">${event.timestamp}</span>
                </div>
                <div class="text-xs text-gray-400 font-mono break-all">
                    ${JSON.stringify(event.data, null, 2)}
                </div>
            `;
            
            // Click handler for session inspection
            div.addEventListener('click', () => {
                if (event.data?.session_id) {
                    this.loadSessionDetail(event.data.session_id);
                }
            });
            
            eventsDiv.prepend(div);
        },
        
        // Filter handling
        setFilter(filter) {
            this.activeFilter = filter;
        },
        
        // Session investigation
        async loadSessionDetail(sessionId) {
            try {
                const resp = await fetch(`/dashboard/api/sessions/${sessionId}`);
                const data = await resp.json();
                this.selectedSession = data;
            } catch (e) {
                console.error('Session load failed:', e);
            }
        },
        
        // Load sessions list for investigation panel
        async loadSessions() {
            // Used by HTMX endpoint
        }
    };
}

// HTMX handlers for partial updates
document.addEventListener('htmx:afterOnLoad', (evt) => {
    // Re-init Alpine on partial loads if needed
});

// Auto-init on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    // Small delay for Alpine to initialize
    setTimeout(() => {
        // Find Alpine component and call init
        document.querySelectorAll('[x-data]').forEach(el => {
            if (el._x_dataStack && el._x_dataStack[0] && typeof el._x_dataStack[0].init === 'function') {
                el._x_dataStack[0].init();
            }
        });
    }, 100);
});