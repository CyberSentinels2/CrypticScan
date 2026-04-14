document.addEventListener('DOMContentLoaded', function () {
    const state = {
        apiBase: localStorage.getItem('crypticscan.apiBase') || 'http://127.0.0.1:5000',
        apiKey: localStorage.getItem('crypticscan.apiKey') || '',
        activeScanId: null,
        pollTimer: null,
        selectedHistoryId: null,
    };

    const apiBaseInput = document.getElementById('apiBaseInput');
    const apiKeyInput = document.getElementById('apiKeyInput');
    const saveSettingsBtn = document.getElementById('saveSettingsBtn');
    const targetInput = document.getElementById('targetInput');
    const toolCheckboxes = Array.from(document.querySelectorAll('.tool-checkbox'));
    const startScanBtn = document.getElementById('startScanBtn');
    const stopScanBtn = document.getElementById('stopScanBtn');
    const statusBadge = document.getElementById('statusBadge');
    const historyList = document.getElementById('historyList');
    const resultsBox = document.getElementById('resultsBox');
    const refreshHistoryBtn = document.getElementById('refreshHistoryBtn');
    const downloadReportBtn = document.getElementById('downloadReportBtn');
    const historySearchInput = document.getElementById('historySearchInput');
    const historyStatusFilter = document.getElementById('historyStatusFilter');
    const healthCheckBtn = document.getElementById('healthCheckBtn');
    const healthBadge = document.getElementById('healthBadge');
    const healthDetails = document.getElementById('healthDetails');
    const toolProgress = document.getElementById('toolProgress');
    const sevCritical = document.getElementById('sevCritical');
    const sevHigh = document.getElementById('sevHigh');
    const sevMedium = document.getElementById('sevMedium');
    const sevLow = document.getElementById('sevLow');
    const sevInfo = document.getElementById('sevInfo');
    let selectedReportScanId = null;

    apiBaseInput.value = state.apiBase;
    apiKeyInput.value = state.apiKey;

    function cleanBaseUrl(url) {
        return (url || '').trim().replace(/\/$/, '');
    }

    function buildHeaders() {
        const headers = {
            'Content-Type': 'application/json',
        };
        if (state.apiKey) {
            headers['X-API-Key'] = state.apiKey;
        }
        return headers;
    }

    async function apiRequest(path, options = {}) {
        const isBodyRequest = options.method && options.method !== 'GET';
        const headers = isBodyRequest ? buildHeaders() : { ...buildHeaders() };
        const response = await fetch(`${state.apiBase}${path}`, {
            ...options,
            headers,
        });

        let payload = null;
        try {
            payload = await response.json();
        } catch (error) {
            payload = null;
        }

        if (!response.ok) {
            const detail = payload && payload.error ? payload.error : `HTTP ${response.status}`;
            throw new Error(detail);
        }

        return payload;
    }

    function setStatus(text, className) {
        statusBadge.textContent = text;
        statusBadge.className = `status-badge ${className}`;
    }

    function setScanButtons(isRunning) {
        startScanBtn.disabled = isRunning;
        stopScanBtn.disabled = !isRunning;
    }

    function setDownloadLink(scanId, enabled) {
        selectedReportScanId = enabled ? scanId : null;
        downloadReportBtn.disabled = !(enabled && scanId);
    }

    function selectedTools() {
        return toolCheckboxes.filter(item => item.checked).map(item => item.value);
    }

    function resetSeverityCards() {
        sevCritical.textContent = '0';
        sevHigh.textContent = '0';
        sevMedium.textContent = '0';
        sevLow.textContent = '0';
        sevInfo.textContent = '0';
    }

    function parseAndRenderSeverity(resultsText) {
        resetSeverityCards();
        if (!resultsText) {
            return;
        }

        const line = resultsText.match(/Critical:\s*(\d+)\s*,\s*High:\s*(\d+)\s*,\s*Medium:\s*(\d+)\s*,\s*Low:\s*(\d+)\s*,\s*Info:\s*(\d+)/i);
        if (!line) {
            return;
        }

        sevCritical.textContent = line[1];
        sevHigh.textContent = line[2];
        sevMedium.textContent = line[3];
        sevLow.textContent = line[4];
        sevInfo.textContent = line[5];
    }

    function renderToolProgress(tools, progressMap) {
        toolProgress.innerHTML = '';
        if (!Array.isArray(tools) || !tools.length) {
            return;
        }

        tools.forEach(tool => {
            const stateValue = progressMap && progressMap[tool] ? progressMap[tool] : 'pending';
            const chip = document.createElement('span');
            chip.className = `tool-chip ${stateValue}`;
            chip.textContent = `${tool}: ${stateValue}`;
            toolProgress.appendChild(chip);
        });
    }

    async function runHealthCheck() {
        try {
            const health = await apiRequest('/healthz');
            const className = health.status === 'ok' ? 'ok' : 'degraded';
            healthBadge.className = `health-badge ${className}`;
            healthBadge.textContent = health.status;

            const toolsText = [
                `nmap=${health.tools && health.tools.nmap ? 'yes' : 'no'}`,
                `zap-cli=${health.tools && health.tools.zap_cli ? 'yes' : 'no'}`,
                `openvas-env=${health.tools && health.tools.openvas_env_configured ? 'yes' : 'no'}`,
            ].join(' | ');

            healthDetails.textContent = `db_ok=${health.db_ok} | api_key_required=${health.api_key_required} | active_scans=${health.active_scans} | ${toolsText}`;
        } catch (error) {
            healthBadge.className = 'health-badge degraded';
            healthBadge.textContent = 'error';
            healthDetails.textContent = `Health check failed: ${error.message}`;
        }
    }

    function clearPolling() {
        if (state.pollTimer) {
            clearInterval(state.pollTimer);
            state.pollTimer = null;
        }
    }

    async function renderScanDetails(scanId) {
        state.selectedHistoryId = scanId;
        const details = await apiRequest(`/scan_results/${scanId}`);
        const tools = Array.isArray(details.tools) ? details.tools.join(', ') : 'n/a';

        resultsBox.textContent =
            `Scan ID: ${scanId}\n` +
            `Status: ${details.status || 'unknown'}\n` +
            `Target: ${details.target || 'n/a'}\n` +
            `Tools: ${tools}\n\n` +
            `${details.results_text || 'No results available yet.'}`;

        parseAndRenderSeverity(details.results_text || '');
        renderToolProgress(details.tools || [], details.tool_progress || {});
        setDownloadLink(scanId, Boolean(details.report));
    }

    async function refreshHistory() {
        historyList.innerHTML = '';
        try {
            const q = encodeURIComponent((historySearchInput.value || '').trim());
            const status = encodeURIComponent((historyStatusFilter.value || '').trim());
            const history = await apiRequest(`/scan_history?limit=30&q=${q}&status=${status}`);
            const items = Array.isArray(history.items) ? history.items : [];

            if (!items.length) {
                const empty = document.createElement('li');
                empty.className = 'history-item';
                empty.textContent = 'No scans match the current filters.';
                historyList.appendChild(empty);
                return;
            }

            items.forEach(item => {
                const li = document.createElement('li');
                li.className = 'history-item';
                if (item.scan_id === state.selectedHistoryId) {
                    li.classList.add('active');
                }
                li.dataset.scanId = item.scan_id;
                li.innerHTML =
                    `<div class="id">${item.scan_id}</div>` +
                    `<div class="meta">${item.target} | ${item.status}</div>`;
                li.addEventListener('click', async function () {
                    Array.from(historyList.querySelectorAll('.history-item')).forEach(node => node.classList.remove('active'));
                    li.classList.add('active');
                    try {
                        await renderScanDetails(item.scan_id);
                    } catch (error) {
                        resultsBox.textContent = `Could not load scan details: ${error.message}`;
                    }
                });
                historyList.appendChild(li);
            });
        } catch (error) {
            const err = document.createElement('li');
            err.className = 'history-item';
            err.textContent = `History unavailable: ${error.message}`;
            historyList.appendChild(err);
        }
    }

    function pollScanStatus(scanId) {
        clearPolling();
        state.pollTimer = setInterval(async function () {
            try {
                const status = await apiRequest(`/scan_status/${scanId}`);
                const statusText = status.status || 'unknown';
                setStatus(statusText.toUpperCase(), statusText);
                renderToolProgress(status.tools || [], status.tool_progress || {});

                if (['completed', 'completed_with_errors', 'cancelled', 'failed', 'unknown'].includes(statusText)) {
                    clearPolling();
                    state.activeScanId = null;
                    setScanButtons(false);
                    await refreshHistory();
                    await renderScanDetails(scanId);
                }
            } catch (error) {
                clearPolling();
                state.activeScanId = null;
                setScanButtons(false);
                setStatus(`ERROR: ${error.message}`, 'error');
            }
        }, 3000);
    }

    saveSettingsBtn.addEventListener('click', async function () {
        state.apiBase = cleanBaseUrl(apiBaseInput.value);
        state.apiKey = apiKeyInput.value.trim();

        localStorage.setItem('crypticscan.apiBase', state.apiBase);
        localStorage.setItem('crypticscan.apiKey', state.apiKey);

        setDownloadLink(state.selectedHistoryId, false);
        await refreshHistory();
        setStatus('SETTINGS SAVED', 'idle');
    });

    startScanBtn.addEventListener('click', async function () {
        const target = targetInput.value.trim();
        const tools = selectedTools();

        if (!target) {
            setStatus('ENTER A TARGET', 'error');
            return;
        }

        if (!tools.length) {
            setStatus('SELECT AT LEAST ONE TOOL', 'error');
            return;
        }

        try {
            const result = await apiRequest('/start_scan', {
                method: 'POST',
                body: JSON.stringify({ ipRange: target, tools }),
            });

            state.activeScanId = result.scan_id;
            setScanButtons(true);
            setStatus(`RUNNING: ${result.scan_id}`, 'running');
            setDownloadLink(result.scan_id, false);
            renderToolProgress(tools, Object.fromEntries(tools.map(tool => [tool, 'pending'])));
            resetSeverityCards();
            resultsBox.textContent = `Scan started for ${target}.\nWaiting for results...`;
            pollScanStatus(result.scan_id);
            await refreshHistory();
        } catch (error) {
            setStatus(`START FAILED: ${error.message}`, 'error');
        }
    });

    stopScanBtn.addEventListener('click', async function () {
        if (!state.activeScanId) {
            return;
        }

        try {
            await apiRequest(`/cancel_scan/${state.activeScanId}`, {
                method: 'POST',
            });
            setStatus('CANCELLING...', 'cancelling');
        } catch (error) {
            setStatus(`CANCEL FAILED: ${error.message}`, 'error');
        }
    });

    refreshHistoryBtn.addEventListener('click', async function () {
        await refreshHistory();
    });

    healthCheckBtn.addEventListener('click', async function () {
        await runHealthCheck();
    });

    historySearchInput.addEventListener('input', function () {
        refreshHistory();
    });

    historyStatusFilter.addEventListener('change', function () {
        refreshHistory();
    });

    downloadReportBtn.addEventListener('click', async function () {
        if (!selectedReportScanId) {
            return;
        }

        try {
            const response = await fetch(`${state.apiBase}/download_report/${selectedReportScanId}`, {
                method: 'GET',
                headers: buildHeaders(),
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const blob = await response.blob();
            const blobUrl = URL.createObjectURL(blob);
            const tempLink = document.createElement('a');
            tempLink.href = blobUrl;
            tempLink.download = `${selectedReportScanId}_report.html`;
            document.body.appendChild(tempLink);
            tempLink.click();
            tempLink.remove();
            URL.revokeObjectURL(blobUrl);
        } catch (error) {
            setStatus(`REPORT DOWNLOAD FAILED: ${error.message}`, 'error');
        }
    });

    setScanButtons(false);
    setStatus('IDLE', 'idle');
    resetSeverityCards();
    runHealthCheck();
    refreshHistory();
});