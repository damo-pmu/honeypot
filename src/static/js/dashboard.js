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
        filters: ['all', 'ssh_attempt', 'telnet_login', 'command', 'attack'],
        activeFilter: 'all',
        selectedIP: null, // For persistent highlight
        
        // Initialize on load
        init() {
            this.loadInitialStats();  // Load from rendered HTML first
            this.loadStats();         // Then fetch fresh data
            this.loadDBEvents();      // Load persisted DB events
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
        
        // Load events from DB (persisted across rebuilds)
        async loadDBEvents() {
            try {
                const resp = await fetch('/dashboard/api/events/history');
                const events = await resp.json();
                events.forEach(e => {
                    this.addEventToFeed(e);
                });
            } catch (e) {
                console.warn('DB events load failed:', e);
            }
        },
        
        // Leaflet map initialization - called after DOM is ready
        initMap() {
            // Prevent double initialization
            if (this.map || window._mapInitialized) return;
            
            const mapEl = document.getElementById('map');
            if (!mapEl) {
                setTimeout(() => this.initMap(), 100);
                return;
            }
            
            // Wait for height to be set
            if (mapEl.offsetHeight === 0) {
                setTimeout(() => this.initMap(), 100);
                return;
            }
            
            this.map = L.map('map').setView([20, 0], 2);
            window._mapInitialized = true;
            
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                attribution: 'Honeypot SOC',
                className: 'map-tiles'
            }).addTo(this.map);
        },
        
        // Geolocate IP and add marker
        async geolocateIP(ip) {
            if (this.markers[ip]) return;
            
            try {
                // Use proxy endpoint to avoid CORS issues
                const resp = await fetch(`/dashboard/api/geolocate/${ip}`);
                const data = await resp.json();
                
                if (data.error || !data.lat) {
                    console.warn('Geolocation failed for:', ip, data.error);
                    return;
                }
                
                const latlng = [data.lat, data.lon];
                const popupContent = `<b>${ip}</b><br>${data.city || ''}, ${data.country || ''}`;
                const marker = L.marker(latlng).addTo(this.map)
                    .bindPopup(popupContent);
                
                // Click marker -> highlight card
                marker.on('click', () => {
                    this.highlightCardByIP(ip);
                    this.addMapGlow();
                });
                
                this.markers[ip] = { marker, latlng };
            } catch (e) {
                console.warn('Geolocation fetch failed:', ip, e);
            }
        },
        
        // Focus map on IP and show popup
        focusOnIP(ip) {
            const m = this.markers[ip];
            if (m && m.marker) {
                this.selectedIP = ip; // Persist selection
                this.map.setView(m.latlng, 8);
                m.marker.openPopup();
                this.addMapGlow();
                // Keep glow on selected IP
            }
        },
        
        // Clear selection
        clearSelection() {
            this.selectedIP = null;
            this.removeMapGlow();
            document.querySelectorAll('.event-card').forEach(el => {
                el.classList.remove('ring-2', 'ring-green-400');
            });
        },
        
        // Highlight card by IP
        highlightCardByIP(ip) {
            document.querySelectorAll('.event-card').forEach(el => {
                el.classList.remove('ring-2', 'ring-green-400');
            });
            
            const card = document.querySelector(`.event-card[data-ip="${ip}"]`);
            if (card) {
                card.classList.add('ring-2', 'ring-green-400');
                card.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        },
        
        // Map glow effect
        addMapGlow() {
            const mapEl = document.getElementById('map');
            if (mapEl) mapEl.classList.add('map-highlight');
        },
        
        removeMapGlow() {
            const mapEl = document.getElementById('map');
            if (mapEl) mapEl.classList.remove('map-highlight');
        },
        
        // SSE stream with resilience - fallback to polling if SSE fails
        initSSE() {
            // Try SSE first
            if (this.trySSE()) return;
            
            // Fallback to polling (works through Cloudflare)
            this.startPolling();
        },
        
        trySSE() {
            try {
                this.evtSource = new EventSource('/dashboard/stream');
                this.connected = true;
                
                this.evtSource.onmessage = (e) => {
                    const event = JSON.parse(e.data);
                    this.addEventToFeed(event);
                };
                
                this.evtSource.onerror = (e) => {
                    // SSE failed (Cloudflare timeout) - switch to polling
                    this.connected = false;
                    this.evtSource.close();
                    console.warn('SSE failed, switching to polling:', e);
                    this.startPolling();
                };
                return true;
            } catch (e) {
                return false;
            }
        },
        
        startPolling() {
            // Poll for new events every 5s (Cloudflare compatible)
            setInterval(async () => {
                const lastCount = this.stats.total_events || 0;
                await this.loadStats();
                if (this.stats.total_events > lastCount) {
                    // Stats changed, fetch recent events
                    this.pollEvents();
                }
            }, 5000);
        },
        
        async pollEvents() {
            try {
                const resp = await fetch('/dashboard/events/recent?limit=10');
                const events = await resp.json();
                events.forEach(e => {
                    // Add to feed if not already there
                    if (!this.events.find(existing => existing.timestamp === e.timestamp)) {
                        this.addEventToFeed(e);
                    }
                });
            } catch (e) {
                console.warn('Polling failed:', e);
            }
        },
        
        // Add event to live feed
        addEventToFeed(event) {
            // Filter check
            if (this.activeFilter !== 'all' && event.type !== this.activeFilter) {
                return;
            }
            
            // Geolocate IP - use attacker_ip field
            const ip = event.data?.attacker_ip || event.data?.ip;
            if (ip) {
                this.geolocateIP(ip);
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
            div.dataset.ip = event.data?.attacker_ip || event.data?.ip || '';
            div.innerHTML = `
                <div class="flex items-center justify-between mb-1">
                    <span class="event-type text-xs px-2 py-0.5 bg-blue-400 text-black rounded">${event.type}</span>
                    <span class="event-time text-xs text-gray-600">${event.timestamp}</span>
                </div>
                <div class="text-xs text-gray-400 font-mono break-all">
                    ${JSON.stringify(event.data, null, 2)}
                </div>
            `;
            
            // Click -> focus map + persist selection + glow
            div.addEventListener('click', () => {
                const ip = event.data?.attacker_ip || event.data?.ip;
                if (ip) {
                    this.selectedIP = ip;
                    this.focusOnIP(ip);
                }
                if (event.data?.session_id) {
                    this.loadSessionDetail(event.data.session_id);
                }
            });
            
            eventsDiv.prepend(div);
        },
        
        // Apply filter to visible events
        applyFilter() {
            document.querySelectorAll('.event-card').forEach(el => {
                const ip = el.dataset.ip;
                // Show/hide based on filter
                el.style.display = this.activeFilter === 'all' || 
                    el.querySelector('.event-type')?.textContent === this.activeFilter ? '' : 'none';
            });
        },
        
        // Filter handling
        setFilter(filter) {
            this.activeFilter = filter;
            this.applyFilter();
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