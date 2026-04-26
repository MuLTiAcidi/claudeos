/**
 * Wolf Alpha — Integrated Terminal
 * Uses xterm.js + Tauri IPC to run a real shell inside the app
 */

class WolfTerminal {
    constructor() {
        this.terminal = null;
        this.isOpen = true;
        this.isTauri = window.__TAURI_INTERNALS__ !== undefined;
        this.init();
    }

    async init() {
        // Dynamically import xterm
        try {
            const { Terminal } = await import('../vendor/xterm.mjs');
            const { FitAddon } = await import('../vendor/addon-fit.mjs');

            this.terminal = new Terminal({
                theme: {
                    background: '#0a0a18',
                    foreground: '#d4d4ee',
                    cursor: '#ff0066',
                    cursorAccent: '#080818',
                    selectionBackground: '#9c27ff44',
                    black: '#0a0a14',
                    red: '#ff2244',
                    green: '#00ff88',
                    yellow: '#ffaa00',
                    blue: '#4488ff',
                    magenta: '#9c27ff',
                    cyan: '#00e5ff',
                    white: '#b0b0cc',
                    brightBlack: '#4a4a6a',
                    brightRed: '#ff4466',
                    brightGreen: '#44ffaa',
                    brightYellow: '#ffcc44',
                    brightBlue: '#66aaff',
                    brightMagenta: '#bb66ff',
                    brightCyan: '#44eeff',
                    brightWhite: '#e8e8ff',
                },
                fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
                fontSize: 16,
                lineHeight: 1.5,
                letterSpacing: 0.5,
                cursorBlink: true,
                cursorStyle: 'bar',
                cursorWidth: 2,
                scrollback: 10000,
                fontWeight: '500',
                fontWeightBold: '700',
            });

            this.fitAddon = new FitAddon();
            this.terminal.loadAddon(this.fitAddon);

            const container = document.getElementById('terminal-container');
            this.terminal.open(container);
            this.fitAddon.fit();

            // Handle resize
            window.addEventListener('resize', () => {
                if (this.isOpen) this.fitAddon.fit();
            });

            // Toggle button
            document.getElementById('btn-toggle-term').addEventListener('click', () => {
                this.toggle();
            });

            if (this.isTauri) {
                await this.connectTauri();
            } else {
                this.connectFallback();
            }
        } catch (e) {
            console.error('Terminal init failed:', e);
            // Fallback — show message in container
            const container = document.getElementById('terminal-container');
            container.innerHTML = '<div style="padding:16px;color:#4a4a6a;font-size:12px;">Terminal requires xterm.js modules. Run with Wolf Alpha server for full terminal.</div>';
        }
    }

    async connectTauri() {
        // Connect to Tauri backend PTY
        const { invoke } = window.__TAURI_INTERNALS__;
        const { listen } = await import('https://unpkg.com/@tauri-apps/api/event');

        try {
            // Spawn terminal process
            await invoke('spawn_terminal');

            // Receive output from PTY
            await listen('terminal-output', (event) => {
                this.terminal.write(event.payload);
            });

            // Send input to PTY
            this.terminal.onData((data) => {
                invoke('write_terminal', { data });
            });

            this.terminal.writeln('\x1b[36m  ClaudeOS Terminal Connected\x1b[0m');
            this.terminal.writeln('\x1b[90m  Type "claude" to start Claude CLI\x1b[0m');
            this.terminal.writeln('');
        } catch (e) {
            console.error('Tauri terminal error:', e);
            this.connectFallback();
        }
    }

    connectFallback() {
        // Fallback — simulated terminal for non-Tauri mode
        this.terminal.writeln('\x1b[36m  Wolf Alpha Terminal\x1b[0m');
        this.terminal.writeln('\x1b[90m  Desktop app required for full terminal.\x1b[0m');
        this.terminal.writeln('\x1b[90m  Use the command bar below for wolf commands.\x1b[0m');
        this.terminal.writeln('');

        let currentLine = '';
        this.terminal.write('\x1b[35mwolf\x1b[0m $ ');

        this.terminal.onData((data) => {
            if (data === '\r') {
                this.terminal.writeln('');
                if (currentLine.trim()) {
                    this.handleFallbackCommand(currentLine.trim());
                }
                currentLine = '';
                this.terminal.write('\x1b[35mwolf\x1b[0m $ ');
            } else if (data === '\x7f') {
                if (currentLine.length > 0) {
                    currentLine = currentLine.slice(0, -1);
                    this.terminal.write('\b \b');
                }
            } else if (data >= ' ') {
                currentLine += data;
                this.terminal.write(data);
            }
        });
    }

    handleFallbackCommand(cmd) {
        if (cmd === 'help') {
            this.terminal.writeln('\x1b[36m  Available in desktop app:\x1b[0m');
            this.terminal.writeln('    claude        — Start Claude CLI');
            this.terminal.writeln('    bash/zsh      — Full shell access');
            this.terminal.writeln('');
            this.terminal.writeln('\x1b[36m  Available now (use command bar below):\x1b[0m');
            this.terminal.writeln('    hunt <target> — Deploy wolves');
            this.terminal.writeln('    deploy <wolf> — Send a wolf');
            this.terminal.writeln('    status        — Pack status');
        } else if (cmd === 'clear') {
            this.terminal.clear();
        } else if (window.wolfDen) {
            window.wolfDen.executeCommand(cmd);
            window.wolfDen.log('TERMINAL', '> ' + cmd);
        } else {
            this.terminal.writeln('\x1b[31m  Command not found: ' + cmd + '\x1b[0m');
        }
    }

    toggle() {
        this.isOpen = !this.isOpen;
        const area = document.getElementById('terminal-area');
        const btn = document.getElementById('btn-toggle-term');

        if (this.isOpen) {
            area.style.height = '250px';
            btn.innerHTML = '&#9660;';
            btn.title = 'Collapse Terminal';
            setTimeout(() => this.fitAddon && this.fitAddon.fit(), 100);
        } else {
            area.style.height = '32px';
            btn.innerHTML = '&#9650;';
            btn.title = 'Expand Terminal';
        }
    }
}

// Init terminal after DOM ready
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
        window.wolfTerminal = new WolfTerminal();
    }, 500);
});
