// script-log-generator.js
// Standalone script monitor for any website (no server reporting)
(function () {
    // Configurable global object for settings
    const config = window.SCRIPT_MONITOR_CONFIG || {};
    const declinedScripts = config.declinedScripts || [];
    const authorizedScripts = config.authorizedScripts || [];

    // Store findings in-memory
    const findings = [];

    // Helper to normalize src (remove query params)
    function normalizeSrc(src) {
        try {
            const url = new URL(src, window.location.origin);
            url.search = '';
            return url.toString();
        } catch (e) {
            return src;
        }
    }

    // Helper to get SHA-256 hash in base64 for CSP
    async function sha256base64(str) {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        return btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));
    }

    // Function to log script details locally, now with HTTP headers for external scripts and SHA-256 hash for inline scripts
    async function logScript(script) {
        const content = script.innerHTML?.trim() || null;
        let src = script.src?.trim() || null;
        let size = 0;
        let hash = '';
        let sha256 = '';
        let headers = null;

        if (src) {
            src = normalizeSrc(src);
            size = src.length;
            hash = btoa(src);
            sha256 = '';
            // Try to fetch headers if CORS allows
            try {
                const response = await fetch(src, { method: 'GET', mode: 'cors' });
                headers = {};
                for (let [key, value] of response.headers.entries()) {
                    headers[key] = value;
                }
            } catch (e) {
                headers = { error: e.message };
            }
        } else if (content) {
            size = content.length;
            hash = btoa(content);
            sha256 = await sha256base64(content);
            headers = null;
        }

        const location = script.parentNode ? script.parentNode.outerHTML.substring(0, 200) : 'Unknown';
        const entry = {
            script_src: src || '',
            script_content: content || '',
            location: location,
            script_size: size,
            script_hash: hash,
            script_sha256: sha256,
            script_headers: headers,
            timestamp: new Date().toISOString(),
        };

        // Only log if not already present (by src/hash/size/content)
        const isDuplicate = findings.some(f =>
            f.script_src === entry.script_src &&
            f.script_hash === entry.script_hash &&
            f.script_size === entry.script_size &&
            f.script_content === entry.script_content
        );
        if (isDuplicate) {
            return;
        }

        findings.push(entry);
        console.log('Script detected:', entry);
    }

    // Log/report every script, block only if declined
    function handleScript(node) {
        (async () => {
            await logScript(node);
            // Block if declined (by src or inline content)
            const src = node.src ? normalizeSrc(node.src) : '';
            const content = node.innerHTML || '';
            if ((src && declinedScripts.includes(src)) ||
                (content && declinedScripts.includes(btoa(content)))) {
                node.remove();
                console.warn('Blocked declined script:', src || content);
            }
        })();
    }

    // Observe the DOM for new <script> elements
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            mutation.addedNodes.forEach((node) => {
                if (node.tagName === 'SCRIPT') {
                    handleScript(node);
                }
            });
        });
    });

    observer.observe(document.documentElement, { childList: true, subtree: true });

    // Optionally, log and check existing scripts on page load
    document.querySelectorAll('script').forEach(handleScript);

    // Expose findings and export function globally
    window.ScriptActivityLogger = {
        getFindings: () => findings.slice(),
        exportFindings: function () {
            const data = JSON.stringify(findings, null, 2);
            const blob = new Blob([data], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'script-activity-log.json';
            document.body.appendChild(a);
            a.click();
            setTimeout(() => {
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }, 100);
        },
        exportFindingsCSV: function () {
            if (!findings.length) return;
            const headers = Object.keys(findings[0]);
            const csvRows = [headers.join(",")];
            for (const entry of findings) {
                const row = headers.map(h => {
                    let val = entry[h] || '';
                    // Escape quotes and commas
                    if (typeof val === 'string') {
                        val = '"' + val.replace(/"/g, '""') + '"';
                    }
                    return val;
                }).join(",");
                csvRows.push(row);
            }
            const csvContent = csvRows.join("\n");
            const blob = new Blob([csvContent], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'script-activity-log.csv';
            document.body.appendChild(a);
            a.click();
            setTimeout(() => {
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }, 100);
        }
    };

    // Automatically export findings to CSV when the page is about to be unloaded
    window.addEventListener('beforeunload', function () {
        if (!findings.length) return;
        const headers = Object.keys(findings[0]);
        const csvRows = [headers.join(",")];
        for (const entry of findings) {
            const row = headers.map(h => {
                let val = entry[h] || '';
                if (typeof val === 'string') {
                    val = '"' + val.replace(/"/g, '""') + '"';
                }
                return val;
            }).join(",");
            csvRows.push(row);
        }
        const csvContent = csvRows.join("\n");
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'script-activity-log.csv';
        document.body.appendChild(a);
        a.click();
        setTimeout(() => {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }, 100);
    });

    // Add a floating download button for CSV export (works on iOS and all browsers)
    function addDownloadButton() {
        if (document.getElementById('script-activity-download-btn')) return;
        const btn = document.createElement('button');
        btn.id = 'script-activity-download-btn';
        btn.textContent = 'Download Script Log CSV';
        btn.style.position = 'fixed';
        btn.style.bottom = '24px';
        btn.style.right = '24px';
        btn.style.zIndex = '2147483647'; // Maximum z-index for overlays
        btn.style.pointerEvents = 'auto'; // Ensure button is clickable
        btn.style.padding = '12px 20px';
        btn.style.background = '#222';
        btn.style.color = '#fff';
        btn.style.border = 'none';
        btn.style.borderRadius = '6px';
        btn.style.boxShadow = '0 2px 8px rgba(0,0,0,0.15)';
        btn.style.fontSize = '16px';
        btn.style.cursor = 'pointer';
        btn.style.opacity = '0.85';
        btn.onmouseenter = () => btn.style.opacity = '1';
        btn.onmouseleave = () => btn.style.opacity = '0.85';
        btn.onclick = function() {
            window.ScriptActivityLogger.exportFindingsCSV();
        };
        document.body.appendChild(btn);
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', addDownloadButton);
    } else {
        addDownloadButton();
    }
})();