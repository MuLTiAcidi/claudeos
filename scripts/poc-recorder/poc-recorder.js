const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

/*
 * ClaudeOS PoC Recorder — REAL SITE PROOF
 * 
 * This records proof from the ACTUAL target website.
 * No generated HTML. Real URLs. Real pages. Real responses.
 * 
 * Usage: node poc-recorder.js <config.json>
 * 
 * Config format:
 * {
 *   "target": "https://bumba.global",
 *   "token": "eyJ...",
 *   "evidence_dir": "/opt/claudeos-hunt/evidence/bumba-2026-04-17",
 *   "steps": [
 *     { "action": "goto", "url": "/en/wallet", "name": "wallet-page", "wait": 3000 },
 *     { "action": "screenshot", "name": "kyc-wall" },
 *     { "action": "console", "code": "fetch(...).then(...)", "name": "api-bypass" },
 *     { "action": "screenshot", "name": "after-bypass" }
 *   ]
 * }
 */

async function record(configPath) {
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    const evidenceDir = config.evidence_dir || '/opt/claudeos-hunt/evidence/' + Date.now();
    const screenshotDir = path.join(evidenceDir, 'screenshots');
    fs.mkdirSync(screenshotDir, { recursive: true });

    // Launch REAL browser with video recording
    const browser = await chromium.launch({ 
        headless: true,
        args: ['--no-sandbox']
    });
    
    const context = await browser.newContext({
        viewport: { width: 1400, height: 900 },
        recordVideo: {
            dir: evidenceDir,
            size: { width: 1400, height: 900 }
        }
    });

    // Set auth cookies/tokens if provided
    if (config.cookies) {
        await context.addCookies(config.cookies);
    }

    const page = await context.newPage();
    
    // Capture ALL console output for evidence
    const consoleLogs = [];
    page.on('console', msg => {
        const text = `[${msg.type()}] ${msg.text()}`;
        consoleLogs.push(text);
        console.log('CONSOLE:', text);
    });

    // Capture ALL network requests for evidence
    const networkLog = [];
    page.on('request', req => {
        if (req.url().includes('graphql') || req.url().includes('api')) {
            networkLog.push({
                method: req.method(),
                url: req.url(),
                headers: req.headers(),
                postData: req.postData()
            });
        }
    });
    page.on('response', async resp => {
        if (resp.url().includes('graphql') || resp.url().includes('api')) {
            try {
                const body = await resp.text();
                networkLog.push({
                    url: resp.url(),
                    status: resp.status(),
                    body: body.substring(0, 2000)
                });
            } catch(e) {}
        }
    });

    let stepNum = 0;

    for (const step of config.steps) {
        stepNum++;
        const label = `Step ${stepNum}: ${step.name || step.action}`;
        console.log(`\n=== ${label} ===`);

        switch (step.action) {
            case 'goto':
                const url = step.url.startsWith('http') ? step.url : config.target + step.url;
                await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 }).catch(() => {});
                if (step.wait) await page.waitForTimeout(step.wait);
                break;

            case 'screenshot':
                // Add a small annotation banner at the top — clearly a label, not fake content
                await page.evaluate((text) => {
                    const existing = document.getElementById('poc-label');
                    if (existing) existing.remove();
                    const div = document.createElement('div');
                    div.id = 'poc-label';
                    div.style.cssText = 'position:fixed;top:0;left:0;right:0;background:rgba(255,0,0,0.9);color:white;padding:5px 10px;z-index:999999;font-size:12px;font-family:monospace;text-align:center;';
                    div.textContent = '🔴 PoC Recording — ' + text + ' — ' + new Date().toISOString();
                    document.body.prepend(div);
                }, step.name || '');
                
                await page.screenshot({
                    path: path.join(screenshotDir, `${String(stepNum).padStart(2,'0')}-${(step.name||'screenshot').replace(/[^a-z0-9]/gi,'-')}.png`),
                    fullPage: step.fullPage || false
                });
                console.log('  Screenshot saved');
                break;

            case 'console':
                // Execute JS in the REAL page context — this is the key
                // The code runs ON the real site, with real cookies, real origin
                try {
                    const result = await page.evaluate(step.code);
                    consoleLogs.push(`[eval] ${JSON.stringify(result)}`);
                } catch(e) {
                    consoleLogs.push(`[eval-error] ${e.message}`);
                }
                if (step.wait) await page.waitForTimeout(step.wait);
                break;

            case 'devtools':
                // Open devtools-style view by showing console output on page
                await page.evaluate((logs) => {
                    const existing = document.getElementById('poc-console');
                    if (existing) existing.remove();
                    const div = document.createElement('div');
                    div.id = 'poc-console';
                    div.style.cssText = 'position:fixed;bottom:0;left:0;right:0;height:40%;background:rgba(0,0,0,0.95);color:#0f0;padding:10px;z-index:999999;font-family:monospace;font-size:12px;overflow-y:auto;border-top:2px solid #ff0000;';
                    div.innerHTML = '<div style="color:#ff6b6b;margin-bottom:5px;">Console Output (Real Site — ' + window.location.hostname + ')</div>' + 
                        logs.map(l => '<div>' + l.replace(/</g,'&lt;') + '</div>').join('');
                    document.body.appendChild(div);
                }, consoleLogs.slice(-20));
                break;

            case 'api':
                // Make API call FROM the browser context (same origin, real cookies)
                const apiResult = await page.evaluate(async (opts) => {
                    const resp = await fetch(opts.url, {
                        method: opts.method || 'POST',
                        headers: opts.headers || {'Content-Type': 'application/json'},
                        body: opts.body ? JSON.stringify(opts.body) : undefined,
                        credentials: 'include'
                    });
                    return { status: resp.status, body: await resp.json() };
                }, step);
                consoleLogs.push(`[API ${step.url}] ${JSON.stringify(apiResult).substring(0, 500)}`);
                console.log('  API result:', JSON.stringify(apiResult).substring(0, 200));
                break;

            case 'click':
                await page.click(step.selector).catch(() => console.log('  Click failed:', step.selector));
                if (step.wait) await page.waitForTimeout(step.wait);
                break;

            case 'type':
                await page.fill(step.selector, step.value).catch(() => console.log('  Type failed'));
                break;

            case 'annotate':
                // Add arrow/highlight to specific element
                await page.evaluate((opts) => {
                    const el = document.querySelector(opts.selector);
                    if (el) {
                        el.style.border = '3px solid red';
                        el.style.boxShadow = '0 0 10px red';
                    }
                }, step);
                break;
        }
    }

    // Save console and network logs
    fs.writeFileSync(path.join(evidenceDir, 'console.log'), consoleLogs.join('\n'));
    fs.writeFileSync(path.join(evidenceDir, 'network.log'), JSON.stringify(networkLog, null, 2));

    console.log('\n=== RECORDING COMPLETE ===');
    console.log('Evidence:', evidenceDir);

    await context.close();
    await browser.close();

    // Rename video
    const vids = fs.readdirSync(evidenceDir).filter(f => f.endsWith('.webm'));
    if (vids.length) {
        fs.renameSync(
            path.join(evidenceDir, vids[vids.length - 1]),
            path.join(evidenceDir, 'poc-recording.webm')
        );
        console.log('Video: poc-recording.webm');
    }
}

const configPath = process.argv[2];
if (!configPath) {
    console.log('Usage: node poc-recorder.js <config.json>');
    console.log('See script header for config format');
    process.exit(1);
}
record(configPath).catch(console.error);
