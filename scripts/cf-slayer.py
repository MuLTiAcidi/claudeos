#!/usr/bin/env python3
"""
ClaudeOS Cloudflare Slayer — Get through the wall.

Usage:
    python3 cf-slayer.py https://target.com
    python3 cf-slayer.py https://target.com --save-cookies cookies.json
    python3 cf-slayer.py https://target.com --load-cookies cookies.json
    python3 cf-slayer.py https://target.com --extract-js
    python3 cf-slayer.py https://target.com --headed  (manual CAPTCHA solving)

Techniques:
    1. Playwright stealth with anti-detection patches
    2. Cookie persistence (solve once, reuse for hours)
    3. Headed mode for manual challenge solving
    4. JS extraction after bypass
"""
import asyncio
import argparse
import json
import os
import sys
import time


STEALTH_SCRIPT = """
// === CLOUDFLARE SLAYER STEALTH PATCHES ===

// 1. Hide webdriver property
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
delete navigator.__proto__.webdriver;

// 2. Add chrome object (missing in headless)
window.chrome = {
    app: {isInstalled: false, InstallState: {DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed'}, RunningState: {CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running'}},
    runtime: {OnInstalledReason: {CHROME_UPDATE: 'chrome_update', INSTALL: 'install', SHARED_MODULE_UPDATE: 'shared_module_update', UPDATE: 'update'}, OnRestartRequiredReason: {APP_UPDATE: 'app_update', OS_UPDATE: 'os_update', PERIODIC: 'periodic'}, PlatformArch: {ARM: 'arm', MIPS: 'mips', MIPS64: 'mips64', X86_32: 'x86-32', X86_64: 'x86-64'}, PlatformNaclArch: {ARM: 'arm', MIPS: 'mips', MIPS64: 'mips64', X86_32: 'x86-32', X86_64: 'x86-64'}, PlatformOs: {ANDROID: 'android', CROS: 'cros', LINUX: 'linux', MAC: 'mac', OPENBSD: 'openbsd', WIN: 'win'}, RequestUpdateCheckStatus: {NO_UPDATE: 'no_update', THROTTLED: 'throttled', UPDATE_AVAILABLE: 'update_available'}},
    loadTimes: function(){return {}},
    csi: function(){return {}}
};

// 3. Fix permissions API
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) => (
    parameters.name === 'notifications' ?
        Promise.resolve({state: Notification.permission}) :
        originalQuery(parameters)
);

// 4. Override plugins (empty = bot)
Object.defineProperty(navigator, 'plugins', {
    get: () => {
        const plugins = [
            {name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format'},
            {name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: ''},
            {name: 'Native Client', filename: 'internal-nacl-plugin', description: ''},
        ];
        plugins.length = 3;
        return plugins;
    }
});

// 5. Fix languages
Object.defineProperty(navigator, 'languages', {
    get: () => ['en-US', 'en']
});

// 6. Fix platform
Object.defineProperty(navigator, 'platform', {
    get: () => 'MacIntel'
});

// 7. Fix hardware concurrency
Object.defineProperty(navigator, 'hardwareConcurrency', {
    get: () => 8
});

// 8. Fix device memory
Object.defineProperty(navigator, 'deviceMemory', {
    get: () => 8
});

// 9. Fix connection
Object.defineProperty(navigator, 'connection', {
    get: () => ({
        downlink: 10,
        effectiveType: '4g',
        rtt: 50,
        saveData: false
    })
});

// 10. WebGL fingerprint normalization
const getParameter = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function(parameter) {
    if (parameter === 37445) return 'Intel Inc.';
    if (parameter === 37446) return 'Intel Iris OpenGL Engine';
    return getParameter.apply(this, arguments);
};
"""


async def solve_cloudflare(url, args):
    from playwright.async_api import async_playwright

    print(f'[*] Cloudflare Slayer targeting: {url}')
    print(f'[*] Mode: {"headed (manual)" if args.headed else "headless (stealth)"}')
    print()

    async with async_playwright() as p:
        # Launch browser
        browser = await p.chromium.launch(
            headless=not args.headed,
            args=[
                '--no-sandbox',
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--disable-features=IsolateOrigins,site-per-process',
                '--disable-setuid-sandbox',
                '--no-first-run',
                '--no-zygote',
            ]
        )

        context = await browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent=args.user_agent or 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            locale='en-US',
            timezone_id='America/New_York',
            color_scheme='light',
            extra_http_headers={
                'X-HackerOne-Research': args.researcher or 'Acidi',
                'Accept-Language': 'en-US,en;q=0.9',
            }
        )

        # Load saved cookies if provided
        if args.load_cookies and os.path.exists(args.load_cookies):
            with open(args.load_cookies) as f:
                cookies = json.load(f)
            await context.add_cookies(cookies)
            print(f'[+] Loaded {len(cookies)} cookies from {args.load_cookies}')

        # Apply stealth patches
        await context.add_init_script(STEALTH_SCRIPT)

        page = await context.new_page()

        # Track Cloudflare challenge status
        cf_challenged = False
        cf_solved = False

        def on_response(resp):
            nonlocal cf_challenged, cf_solved
            if resp.status == 403 and 'cf-mitigated' in str(resp.headers):
                cf_challenged = True
            if resp.status == 200 and cf_challenged:
                cf_solved = True

        page.on('response', on_response)

        # Navigate to target
        print(f'[*] Navigating to {url}...')
        try:
            await page.goto(url, wait_until='domcontentloaded', timeout=30000)
        except Exception as e:
            print(f'[!] Navigation error: {e}')

        # Wait for Cloudflare challenge to resolve
        print('[*] Waiting for Cloudflare challenge...')
        for i in range(30):
            await page.wait_for_timeout(1000)

            # Check if we got through
            title = await page.title()
            current_url = page.url

            # Cloudflare challenge pages have specific titles
            if 'Just a moment' in title or 'Checking your browser' in title:
                if i == 0:
                    print(f'[*] Cloudflare challenge detected: "{title}"')
                if args.headed:
                    print(f'[*] Solve the challenge in the browser window... ({30-i}s remaining)')
                continue
            elif 'Attention Required' in title or 'Access denied' in title:
                print(f'[!] Cloudflare blocked: {title}')
                break
            else:
                # We got through!
                print(f'[+] CHALLENGE SOLVED! Title: {title}')
                cf_solved = True
                break

        if not cf_solved:
            # Last check
            title = await page.title()
            if 'Just a moment' not in title and 'Access denied' not in title:
                cf_solved = True
                print(f'[+] Page loaded: {title}')

        # Results
        print()
        final_url = page.url
        final_title = await page.title()
        status = 'SOLVED' if cf_solved else 'BLOCKED'

        print(f'[{"+" if cf_solved else "!"}] Status: {status}')
        print(f'[*] URL: {final_url}')
        print(f'[*] Title: {final_title}')

        if cf_solved:
            # Save cookies
            cookies = await context.cookies()
            cf_cookies = [c for c in cookies if 'cf_clearance' in c['name'] or '__cf' in c['name']]
            print(f'[+] Cloudflare cookies: {len(cf_cookies)}')
            for c in cf_cookies:
                print(f'    {c["name"]}: {c["value"][:50]}...')

            if args.save_cookies:
                with open(args.save_cookies, 'w') as f:
                    json.dump(cookies, f, indent=2)
                print(f'[+] All cookies saved to {args.save_cookies}')

            # Extract JS if requested
            if args.extract_js:
                print(f'\n[*] Extracting JS bundles...')
                scripts = await page.evaluate('Array.from(document.querySelectorAll("script[src]")).map(s => s.src)')
                print(f'[+] JS files ({len(scripts)}):')
                for s in scripts[:20]:
                    print(f'    {s[:120]}')

                # Extract API endpoints from JS
                import re
                all_endpoints = set()
                for js_url in scripts[:15]:
                    try:
                        content = await page.evaluate(f'fetch("{js_url}").then(r => r.text())')
                        if not content or len(content) < 200:
                            continue
                        for m in re.finditer(r'["\'](/api/[a-zA-Z0-9/_.-]+)["\']', content):
                            all_endpoints.add(m.group(1))
                        for m in re.finditer(r'["\'](/v[0-9]/[a-zA-Z0-9/_.-]+)["\']', content):
                            all_endpoints.add(m.group(1))
                    except:
                        pass

                if all_endpoints:
                    print(f'\n[+] API endpoints ({len(all_endpoints)}):')
                    for ep in sorted(all_endpoints):
                        print(f'    {ep}')

            # Show page content preview
            text = await page.evaluate('document.body.innerText.substring(0, 500)')
            print(f'\n[+] Page content:\n{text[:500]}')

            # Take screenshot
            screenshot = args.screenshot or '/tmp/cf-slayer-result.png'
            await page.screenshot(path=screenshot)
            print(f'\n[+] Screenshot: {screenshot}')

        else:
            # Save screenshot of the block page
            await page.screenshot(path='/tmp/cf-slayer-blocked.png')
            print(f'[!] Screenshot: /tmp/cf-slayer-blocked.png')
            print(f'[*] Try: --headed mode for manual challenge solving')

        await browser.close()

    return cf_solved


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='ClaudeOS Cloudflare Slayer')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('--headed', action='store_true', help='Use headed mode (for manual CAPTCHA)')
    parser.add_argument('--save-cookies', help='Save cookies to file after solving')
    parser.add_argument('--load-cookies', help='Load cookies from file')
    parser.add_argument('--extract-js', action='store_true', help='Extract JS bundles after bypass')
    parser.add_argument('--screenshot', help='Screenshot output path')
    parser.add_argument('--user-agent', help='Custom user agent')
    parser.add_argument('--researcher', default='Acidi', help='HackerOne username for X-HackerOne-Research header')
    args = parser.parse_args()

    result = asyncio.run(solve_cloudflare(args.url, args))
    sys.exit(0 if result else 1)
