/**
 * IDS COMMAND CENTER — LIVE DASHBOARD LOGIC (SSE, CHARTS, ALERTS & DROPDOWN SIMULATOR)
 */

document.addEventListener('DOMContentLoaded', () => {
    // --- State Variables ---
    let lastProcessedCount = 0;
    let lastTimestamp = Date.now();
    const historyPoints = 25;
    let chartHistory = Array(historyPoints).fill(12);
    let chartAlertsHistory = Array(historyPoints).fill(8);
    const startTime = Date.now();

    // --- DOM Elements ---
    const valProcessed = document.getElementById('val-processed');
    const valPps = document.getElementById('val-pps');
    const valAlerts = document.getElementById('val-alerts');
    const valThreatLevel = document.getElementById('val-threat-level');
    const valWorkers = document.getElementById('val-workers');
    const valDropped = document.getElementById('val-dropped');
    const uptimeDisplay = document.getElementById('uptime-display');
    const alertsTbody = document.getElementById('alerts-tbody');
    const alertsBadge = document.getElementById('alerts-badge');
    const cardAlerts = document.getElementById('card-alerts');

    // Simulator Dropdown
    const btnSimDropdown = document.getElementById('btn-sim-dropdown');
    const simDropdownWrapper = document.querySelector('.sim-dropdown-wrapper');
    const btnSimPortScan = document.getElementById('btn-sim-portscan');
    const btnSimSynFlood = document.getElementById('btn-sim-synflood');
    const btnSimBruteForce = document.getElementById('btn-sim-bruteforce');

    // Monitor Control Buttons
    const btnMonitorStart = document.getElementById('btn-monitor-start');
    const btnMonitorRestart = document.getElementById('btn-monitor-restart');
    const btnMonitorStop = document.getElementById('btn-monitor-stop');

    // Toggle Simulator Dropdown
    if (btnSimDropdown && simDropdownWrapper) {
        btnSimDropdown.addEventListener('click', (e) => {
            e.stopPropagation();
            simDropdownWrapper.classList.toggle('open');
        });

        // Close on click outside
        document.addEventListener('click', (e) => {
            if (!simDropdownWrapper.contains(e.target)) {
                simDropdownWrapper.classList.remove('open');
            }
        });
    }

    // --- Canvas Chart setup ---
    const canvas = document.getElementById('traffic-chart');
    const ctx = canvas ? canvas.getContext('2d') : null;

    function resizeCanvas() {
        if (!canvas || !canvas.parentElement) return;
        const rect = canvas.parentElement.getBoundingClientRect();
        canvas.width = rect.width;
        canvas.height = rect.height;
        renderChart();
    }
    window.addEventListener('resize', resizeCanvas);
    setTimeout(resizeCanvas, 50);

    // --- Uptime Counter ---
    setInterval(() => {
        const elapsedSec = Math.floor((Date.now() - startTime) / 1000);
        const hrs = String(Math.floor(elapsedSec / 3600)).padStart(2, '0');
        const mins = String(Math.floor((elapsedSec % 3600) / 60)).padStart(2, '0');
        const secs = String(elapsedSec % 60).padStart(2, '0');
        if (uptimeDisplay) uptimeDisplay.textContent = `${hrs}:${mins}:${secs}`;
    }, 1000);

    // --- Chart Rendering ---
    function renderChart() {
        if (!ctx || !canvas) return;
        const w = canvas.width;
        const h = canvas.height;

        ctx.clearRect(0, 0, w, h);

        const paddingLeft = 36;
        const paddingRight = 16;
        const paddingTop = 20;
        const paddingBottom = 26;
        const chartW = w - paddingLeft - paddingRight;
        const chartH = h - paddingTop - paddingBottom;

        // Dynamic max scale with base 200
        const maxData = Math.max(...chartHistory, ...chartAlertsHistory, 20);
        const maxVal = maxData > 200 ? Math.ceil(maxData / 50) * 50 : 200;

        // Y-axis grid lines and labels (0, 50, 100, 150, 200)
        const ySteps = 4;
        ctx.fillStyle = '#627290';
        ctx.font = '10px JetBrains Mono, monospace';
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';

        for (let i = 0; i <= ySteps; i++) {
            const val = Math.round((maxVal / ySteps) * i);
            const y = paddingTop + chartH - (i / ySteps) * chartH;

            // Horizontal grid line
            ctx.beginPath();
            ctx.strokeStyle = 'rgba(255, 255, 255, 0.04)';
            ctx.lineWidth = 1;
            ctx.moveTo(paddingLeft, y);
            ctx.lineTo(w - paddingRight, y);
            ctx.stroke();

            // Label
            ctx.fillText(val.toString(), paddingLeft - 8, y);
        }

        // X-axis timestamps at bottom
        const now = Date.now();
        const numLabels = 6;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';

        for (let i = 0; i < numLabels; i++) {
            const x = paddingLeft + (i / (numLabels - 1)) * chartW;
            const timeOffsetSec = (numLabels - 1 - i) * 12; // 60s window
            const labelTime = new Date(now - timeOffsetSec * 1000);
            const hrs = String(labelTime.getHours()).padStart(2, '0');
            const mins = String(labelTime.getMinutes()).padStart(2, '0');
            const secs = String(labelTime.getSeconds()).padStart(2, '0');
            const timeStr = secs === '00' ? `${hrs}:${mins}` : `${hrs}:${mins}:${secs}`;
            ctx.fillText(timeStr, x, h - paddingBottom + 8);
        }

        const stepX = chartW / (chartHistory.length - 1);

        // Function to draw smooth spline with area
        function drawAreaAndLine(data, strokeColor, fillColor, glowColor) {
            if (data.length < 2) return;

            const points = data.map((val, i) => ({
                x: paddingLeft + i * stepX,
                y: paddingTop + chartH - (Math.min(val, maxVal) / maxVal) * chartH
            }));

            // Area fill
            ctx.beginPath();
            ctx.moveTo(points[0].x, paddingTop + chartH);
            ctx.lineTo(points[0].x, points[0].y);

            for (let i = 0; i < points.length - 1; i++) {
                const xc = (points[i].x + points[i + 1].x) / 2;
                const yc = (points[i].y + points[i + 1].y) / 2;
                ctx.quadraticCurveTo(points[i].x, points[i].y, xc, yc);
            }
            ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);
            ctx.lineTo(points[points.length - 1].x, paddingTop + chartH);
            ctx.closePath();

            const grad = ctx.createLinearGradient(0, paddingTop, 0, paddingTop + chartH);
            grad.addColorStop(0, fillColor);
            grad.addColorStop(1, 'rgba(0, 0, 0, 0)');
            ctx.fillStyle = grad;
            ctx.fill();

            // Line stroke
            ctx.beginPath();
            ctx.moveTo(points[0].x, points[0].y);

            for (let i = 0; i < points.length - 1; i++) {
                const xc = (points[i].x + points[i + 1].x) / 2;
                const yc = (points[i].y + points[i + 1].y) / 2;
                ctx.quadraticCurveTo(points[i].x, points[i].y, xc, yc);
            }
            ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);

            ctx.save();
            ctx.strokeStyle = strokeColor;
            ctx.lineWidth = 2.2;
            ctx.shadowColor = glowColor;
            ctx.shadowBlur = 10;
            ctx.stroke();
            ctx.restore();
        }

        // Draw Baseline/Alerts Curve (Pink/Magenta)
        drawAreaAndLine(
            chartAlertsHistory,
            '#ff2d75',
            'rgba(255, 45, 117, 0.18)',
            '#ff2d75'
        );

        // Draw Traffic/Packets Curve (Cyan)
        drawAreaAndLine(
            chartHistory,
            '#00f2fe',
            'rgba(0, 242, 254, 0.22)',
            '#00f2fe'
        );
    }

    // --- Update KPI Metrics ---
    function updateStats(stats) {
        if (!stats) return;

        // Packets count & PPS
        const currentProcessed = stats.processedCount || 0;
        const now = Date.now();
        const timeDiff = (now - lastTimestamp) / 1000;
        const pps = (timeDiff > 0 && lastProcessedCount > 0)
            ? Math.max(0, Math.round((currentProcessed - lastProcessedCount) / timeDiff))
            : 0;

        lastProcessedCount = currentProcessed;
        lastTimestamp = now;

        if (valProcessed) valProcessed.textContent = currentProcessed.toLocaleString();
        if (valPps) valPps.textContent = `${pps} pps`;

        // Alerts count
        const alertCount = stats.alertCount || 0;
        if (valAlerts) valAlerts.textContent = alertCount.toLocaleString();

        if (valThreatLevel && cardAlerts) {
            if (alertCount > 0) {
                valThreatLevel.textContent = ` ${alertCount} AMENAZAS`;
                valThreatLevel.className = 'threat-status high-threat';
                cardAlerts.classList.add('has-threats');
            } else {
                valThreatLevel.textContent = 'ESTADO NORMAL';
                valThreatLevel.className = 'threat-status';
                cardAlerts.classList.remove('has-threats');
            }
        }

        // Workers & Backpressure
        if (valWorkers) valWorkers.textContent = stats.workerCount || 8;
        if (valDropped) valDropped.textContent = (stats.droppedCount || 0).toLocaleString();

        // Push new points to chart
        chartHistory.shift();
        chartHistory.push(Math.max(10, pps));

        chartAlertsHistory.shift();
        chartAlertsHistory.push(Math.max(5, alertCount * 4 + Math.round(Math.random() * 4)));

        renderChart();
    }

    // --- Format Time Helper (e.g. "12:55:26 p. m.") ---
    function formatAlertTime(ts) {
        if (!ts) return new Date().toLocaleTimeString('es-ES');
        try {
            const d = new Date(ts);
            return d.toLocaleTimeString('es-ES');
        } catch {
            return new Date().toLocaleTimeString('es-ES');
        }
    }

    // --- Delete Alert Item from History ---
    function deleteAlertRow(rowElement, alert) {
        rowElement.style.opacity = '0';
        rowElement.style.transform = 'translateX(20px)';
        rowElement.style.transition = 'all 0.25s ease';

        setTimeout(() => {
            rowElement.remove();
            updateAlertsCountBadge();

            if (alertsTbody && alertsTbody.children.length === 0) {
                alertsTbody.innerHTML = `
                    <div class="empty-state" id="empty-alerts-row">
                        <p>No hay alertas activas en el registro.</p>
                    </div>
                `;
            }
        }, 250);

        // Delete from backend
        if (alert && alert.timestamp) {
            fetch(`/api/alerts?ts=${encodeURIComponent(alert.timestamp)}`, { method: 'DELETE' })
                .catch(err => console.debug('Error deleting alert:', err));
        }
    }

    function updateAlertsCountBadge() {
        if (!alertsBadge || !alertsTbody) return;
        const count = alertsTbody.querySelectorAll('.suspicious-row').length;
        alertsBadge.textContent = `${count} Eventos`;
    }

    // --- Render Suspicious Alert Row ---
    function renderAlertRow(alert, isNew = false) {
        if (!alert || !alertsTbody) return;

        const empty = document.getElementById('empty-alerts-row');
        if (empty) empty.remove();

        const row = document.createElement('div');
        row.className = 'suspicious-row';
        if (isNew) row.classList.add('row-new');

        let badgeClass = 'badge-port-scan';
        let badgeText = alert.eventType || 'PORT_SCAN';

        if (alert.eventType === 'PORT_SCAN') {
            badgeClass = 'badge-port-scan';
            badgeText = 'PORT_SCAN';
        } else if (alert.eventType === 'BRUTE_FORCE') {
            badgeClass = 'badge-brute-force';
            badgeText = 'BRUTE_FORCE';
        } else if (alert.eventType === 'SYN_FLOOD') {
            badgeClass = 'badge-syn-flood';
            badgeText = 'SYN_FLOOD';
        }

        const timeStr = formatAlertTime(alert.timestamp);
        const ipDisplay = alert.srcPort ? `${alert.srcIp || '0.0.0.0'}:${alert.srcPort}` : (alert.srcIp || '0.0.0.0');

        const dstDisplay = alert.dstPort ? `${alert.dstIp || '0.0.0.0'}:${alert.dstPort}` : (alert.dstIp || '0.0.0.0');

        row.innerHTML = `
            <span class="cell-hora mono">${timeStr}</span>
            <span class="cell-tipo"><span class="badge-attack ${badgeClass}">${badgeText}</span></span>
            <span class="cell-ip mono" title="${ipDisplay}">${ipDisplay}</span>
            <span class="cell-dst mono" title="${dstDisplay}">${dstDisplay}</span>
            <button class="btn-trash" title="Eliminar Alerta">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="3 6 5 6 21 6" />
                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                </svg>
            </button>
        `;

        const btnTrash = row.querySelector('.btn-trash');
        if (btnTrash) {
            btnTrash.addEventListener('click', () => deleteAlertRow(row, alert));
        }

        alertsTbody.insertBefore(row, alertsTbody.firstChild);

        // Keep maximum 100 rows in DOM
        while (alertsTbody.children.length > 100) {
            alertsTbody.removeChild(alertsTbody.lastChild);
        }

        updateAlertsCountBadge();
    }

    // --- Polling & SSE Stream Connection ---
    function fetchInitialData() {
        // Fetch stats
        fetch('/api/stats')
            .then(res => res.json())
            .then(stats => updateStats(stats))
            .catch(err => console.debug('Stats poll:', err));

        // Fetch alerts history
        fetch('/api/alerts')
            .then(res => res.json())
            .then(alerts => {
                if (Array.isArray(alerts) && alerts.length > 0) {
                    alerts.reverse().forEach(a => renderAlertRow(a, false));
                }
            })
            .catch(err => console.debug('Alerts poll:', err));
    }

    fetchInitialData();
    setInterval(fetchInitialData, 1500);

    // Setup Server-Sent Events (SSE)
    if (!!window.EventSource) {
        const eventSource = new EventSource('/api/stream');
        eventSource.onmessage = (e) => {
            try {
                const data = JSON.parse(e.data);
                if (data.type === 'ALERT') {
                    renderAlertRow(data.event, true);
                } else if (data.type === 'STATS') {
                    updateStats(data.stats);
                }
            } catch (err) {
                console.debug('SSE parse error:', err);
            }
        };
    }

    // --- Simulator Trigger Handler ---
    function triggerSimulation(type) {
        if (simDropdownWrapper) {
            simDropdownWrapper.classList.remove('open');
        }

        fetch(`/api/simulate?type=${type}`, { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                console.log(`Simulación ${type}:`, data);
                fetchInitialData();
            })
            .catch(err => console.error(`Error simulando ${type}:`, err));
    }

    if (btnSimPortScan) {
        btnSimPortScan.addEventListener('click', () => triggerSimulation('portscan'));
    }
    if (btnSimSynFlood) {
        btnSimSynFlood.addEventListener('click', () => triggerSimulation('synflood'));
    }
    if (btnSimBruteForce) {
        btnSimBruteForce.addEventListener('click', () => triggerSimulation('bruteforce'));
    }

    // --- Monitor Controls ---
    function updateMonitorUI(state) {
        const isRunning = state === 'RUNNING';
        const isStopped = state === 'STOPPED';
        const isTransitioning = state === 'STARTING' || state === 'STOPPING';

        if (btnMonitorStart) {
            btnMonitorStart.disabled = isRunning || isTransitioning;
            btnMonitorStart.classList.toggle('active', isRunning);
        }
        if (btnMonitorRestart) {
            btnMonitorRestart.disabled = isStopped || isTransitioning;
        }
        if (btnMonitorStop) {
            btnMonitorStop.disabled = isStopped || isTransitioning;
        }
    }

    function fetchMonitorState() {
        fetch('/api/monitor')
            .then(res => res.json())
            .then(data => updateMonitorUI(data.state || 'UNKNOWN'))
            .catch(() => updateMonitorUI('UNKNOWN'));
    }

    function triggerMonitorAction(action) {
        if (btnMonitorStart) btnMonitorStart.disabled = true;
        if (btnMonitorRestart) btnMonitorRestart.disabled = true;
        if (btnMonitorStop) btnMonitorStop.disabled = true;

        fetch(`/api/monitor?action=${action}`, { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                updateMonitorUI(data.state || 'UNKNOWN');
                setTimeout(fetchMonitorState, 1000);
            })
            .catch(err => {
                console.error(`Error en monitor ${action}:`, err);
                fetchMonitorState();
            });
    }

    if (btnMonitorStart) {
        btnMonitorStart.addEventListener('click', () => triggerMonitorAction('start'));
    }
    if (btnMonitorRestart) {
        btnMonitorRestart.addEventListener('click', () => triggerMonitorAction('restart'));
    }
    if (btnMonitorStop) {
        btnMonitorStop.addEventListener('click', () => triggerMonitorAction('stop'));
    }

    fetchMonitorState();
    setInterval(fetchMonitorState, 2500);
});
