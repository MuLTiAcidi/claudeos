/**
 * Wolf Alpha — Cyberpunk Command Center
 * The Alpha's throne. Each sector = a building. Wolves await commands.
 */

// =========================================================================
// Particle Background
// =========================================================================
class ParticleField {
    constructor() {
        this.canvas = document.getElementById('particles-bg');
        this.ctx = this.canvas.getContext('2d');
        this.particles = [];
        this.resize();
        this.init();
        window.addEventListener('resize', () => this.resize());
    }

    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
    }

    init() {
        for (let i = 0; i < 80; i++) {
            this.particles.push({
                x: Math.random() * this.canvas.width,
                y: Math.random() * this.canvas.height,
                size: Math.random() * 1.5 + 0.3,
                speedX: (Math.random() - 0.5) * 0.2,
                speedY: -Math.random() * 0.3 - 0.1,
                opacity: Math.random() * 0.4 + 0.1,
                color: ['#ff0066', '#00e5ff', '#9c27ff', '#00ff88'][Math.floor(Math.random() * 4)],
                pulse: Math.random() * Math.PI * 2,
            });
        }
    }

    update() {
        this.particles.forEach(p => {
            p.x += p.speedX;
            p.y += p.speedY;
            p.pulse += 0.02;
            if (p.y < -10) { p.y = this.canvas.height + 10; p.x = Math.random() * this.canvas.width; }
            if (p.x < 0) p.x = this.canvas.width;
            if (p.x > this.canvas.width) p.x = 0;
        });
    }

    draw() {
        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
        const grd = this.ctx.createRadialGradient(
            this.canvas.width / 2, this.canvas.height * 0.7, 0,
            this.canvas.width / 2, this.canvas.height * 0.7, this.canvas.width * 0.6
        );
        grd.addColorStop(0, 'rgba(156, 39, 255, 0.04)');
        grd.addColorStop(0.5, 'rgba(255, 0, 102, 0.02)');
        grd.addColorStop(1, 'transparent');
        this.ctx.fillStyle = grd;
        this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);

        this.particles.forEach(p => {
            const a = p.opacity * (Math.sin(p.pulse) * 0.3 + 0.7);
            this.ctx.beginPath();
            this.ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
            this.ctx.fillStyle = p.color;
            this.ctx.globalAlpha = a;
            this.ctx.fill();
            this.ctx.globalAlpha = 1;
        });
    }
}

// =========================================================================
// Wolf Alpha — Command Center Engine
// =========================================================================
class WolfDen {
    constructor() {
        this.canvas = document.getElementById('wolf-canvas');
        this.ctx = this.canvas.getContext('2d');
        this.agents = [];
        this.sectors = {};
        this.sectorOrder = [];
        this.buildings = [];
        this.selectedAgent = null;
        this.selectedBuilding = null;
        this.hoveredBuilding = null;
        this.hoveredAgent = null;
        this.scroll = { x: 0, y: 0 };
        this.isDragging = false;
        this.zoom = 1;
        this.time = 0;
        this.activeAgents = new Set();
        this.findings = 0;
        this.particles = new ParticleField();
        this.dataFlows = [];

        this.resize();
        this.bindEvents();
        this.loadAgents();
    }

    resize() {
        const rect = this.canvas.parentElement.getBoundingClientRect();
        const dpr = window.devicePixelRatio || 1;
        this.canvas.width = rect.width * dpr;
        this.canvas.height = rect.height * dpr;
        this.canvas.style.width = rect.width + 'px';
        this.canvas.style.height = rect.height + 'px';
        this.ctx.scale(dpr, dpr);
        this.width = rect.width;
        this.height = rect.height;
    }

    async loadAgents() {
        const resp = await fetch('/api/agents');
        this.agents = await resp.json();
        this.buildSectors();
        this.layoutBuildings();
        this.renderSectorPanel();
        this.animate();
        this.log('SYSTEM', `${this.agents.length} wolves loaded across ${this.sectorOrder.length} sectors.`);

        // Auto-poll for CLI findings every 2 seconds
        this.startAutoPolling();
    }

    buildSectors() {
        this.sectors = {};
        this.agents.forEach(a => {
            if (!this.sectors[a.sector]) {
                this.sectors[a.sector] = { color: a.color, agents: [] };
                this.sectorOrder.push(a.sector);
            }
            this.sectors[a.sector].agents.push(a);
        });
    }

    layoutBuildings() {
        this.buildings = [];
        const cols = 4;
        const padX = 20;
        const padY = 20;
        const bw = (this.width - padX * (cols + 1)) / cols;
        const bh_base = 60;

        this.sectorOrder.forEach((name, i) => {
            const sector = this.sectors[name];
            const col = i % cols;
            const row = Math.floor(i / cols);
            const wolfRows = Math.ceil(sector.agents.length / 10);
            const bh = bh_base + wolfRows * 18;

            // Calculate y based on previous buildings in same column
            let y = padY;
            for (let prev = col; prev < i; prev += cols) {
                const prevSector = this.sectors[this.sectorOrder[prev]];
                const prevWolfRows = Math.ceil(prevSector.agents.length / 10);
                y += bh_base + prevWolfRows * 18 + padY;
            }

            const bld = {
                name: name,
                x: padX + col * (bw + padX),
                y: y,
                w: bw,
                h: bh,
                color: sector.color,
                agents: sector.agents,
                activeCount: 0,
            };

            // Position wolves inside building
            const wolfPad = 8;
            const wolfSize = 6;
            const wolfGap = 4;
            const wolvesPerRow = Math.floor((bw - wolfPad * 2) / (wolfSize * 2 + wolfGap));

            sector.agents.forEach((agent, ai) => {
                const wr = Math.floor(ai / wolvesPerRow);
                const wc = ai % wolvesPerRow;
                agent.bx = bld.x + wolfPad + wc * (wolfSize * 2 + wolfGap) + wolfSize;
                agent.by = bld.y + 48 + wr * (wolfSize * 2 + wolfGap) + wolfSize;
                agent.radius = agent.sector === 'Elite Wolves' ? 5 : 3.5;
                agent.phase = Math.random() * Math.PI * 2;
                agent.building = bld;
            });

            this.buildings.push(bld);
        });

        // Calculate total content height for scrolling
        this.contentHeight = Math.max(...this.buildings.map(b => b.y + b.h)) + padY;
    }

    renderSectorPanel() {
        const container = document.getElementById('sector-buildings');
        container.innerHTML = '';
        const maxCount = Math.max(...Object.values(this.sectors).map(s => s.agents.length));

        this.sectorOrder.forEach(name => {
            const sector = this.sectors[name];
            const bld = document.createElement('div');
            bld.className = 'sector-building';
            bld.innerHTML = `
                <div style="position:absolute;top:0;left:0;width:3px;height:100%;background:${sector.color};border-radius:3px 0 0 3px;"></div>
                <div class="sector-building-name">${name}</div>
                <div class="sector-building-count">${sector.agents.length} wolves</div>
                <div class="sector-building-bar">
                    <div class="sector-building-fill" style="width:${(sector.agents.length/maxCount)*100}%;background:${sector.color}"></div>
                </div>
            `;
            bld.onclick = () => {
                const building = this.buildings.find(b => b.name === name);
                if (building) {
                    this.scroll.y = -building.y + 20;
                    this.selectedBuilding = building;
                }
            };
            container.appendChild(bld);
        });
    }

    // =====================================================================
    // Command Chain
    // =====================================================================
    executeCommand(cmd) {
        const parts = cmd.trim().toLowerCase().split(/\s+/);
        const action = parts[0];
        const target = parts[1];
        const arg = parts.slice(2).join(' ');

        switch (action) {
            case 'deploy': case 'send': this.cmdDeploy(target, arg); break;
            case 'recall': this.cmdRecall(target); break;
            case 'status': this.cmdStatus(); break;
            case 'hunt': this.cmdHunt(target); break;
            case 'stop': this.cmdRecall('all'); break;
            case 'help': this.cmdHelp(); break;
            case 'find': this.cmdFind(target); break;
            case 'clear': document.getElementById('activity-log').innerHTML = ''; this.log('SYSTEM', 'Log cleared.'); break;
            default: this.log('SYSTEM', `Unknown: "${action}". Type "help".`, 'alert');
        }
    }

    cmdDeploy(name, target) {
        if (!name) { this.log('SYSTEM', 'Usage: deploy <wolf-name> [target]', 'alert'); return; }
        const agent = this.agents.find(a => a.name === name || a.display_name.toLowerCase().includes(name));
        if (!agent) { this.log('SYSTEM', `Wolf "${name}" not found. Try "find ${name}".`, 'alert'); return; }
        this.activeAgents.add(agent.id);
        agent.status = 'active';
        this.updateStats();
        this.log(agent.display_name, `Deployed${target ? ' on ' + target : ''}. Engaging...`, 'deploy');
    }

    cmdRecall(name) {
        if (name === 'all') {
            this.activeAgents.clear();
            this.agents.forEach(a => a.status = 'idle');
            this.updateStats();
            this.log('SYSTEM', 'All wolves recalled.');
            return;
        }
        const agent = this.agents.find(a => a.name === name);
        if (agent) {
            this.activeAgents.delete(agent.id);
            agent.status = 'idle';
            this.updateStats();
            this.log(agent.display_name, 'Recalled.');
        }
    }

    cmdHunt(target) {
        if (!target) { this.log('SYSTEM', 'Usage: hunt <target.com>', 'alert'); return; }
        this.log('ALPHA', `Initiating real hunt on ${target}...`, 'deploy');

        // Deploy visual wolves
        const hunters = ['shadow-recon', 'tech-stack-detector', 'recon-master', 'network-mapper'];
        let delay = 0;
        hunters.forEach(name => {
            setTimeout(() => this.cmdDeploy(name, target), delay);
            delay += 400;
        });

        // Start REAL hunt via backend
        fetch('/api/hunt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: target })
        }).then(r => r.json()).then(data => {
            if (data.error) {
                this.log('SYSTEM', data.error, 'alert');
            } else {
                this.log('ALPHA', `Wolves deployed on ${target}. Intel incoming...`, 'deploy');
                this.showTab('findings');
                this.startFindingsPolling();
            }
        });
    }

    cmdFind(query) {
        if (!query) { this.log('SYSTEM', 'Usage: find <keyword>', 'alert'); return; }
        const matches = this.agents.filter(a =>
            a.name.includes(query) || a.display_name.toLowerCase().includes(query) || a.sector.toLowerCase().includes(query)
        );
        if (matches.length === 0) { this.log('SYSTEM', `No wolves matching "${query}".`); return; }
        this.log('SYSTEM', `Found ${matches.length} wolves:`);
        matches.slice(0, 8).forEach(a => this.log('', `  ${a.name} [${a.sector}]`));
        if (matches.length > 8) this.log('', `  ... and ${matches.length - 8} more`);
    }

    cmdStatus() {
        this.log('SYSTEM', `Pack: ${this.agents.length} | Active: ${this.activeAgents.size} | Findings: ${this.findings}`);
        if (this.activeAgents.size > 0) {
            this.activeAgents.forEach(id => {
                const a = this.agents.find(ag => ag.id === id);
                if (a) this.log('', `  ${a.display_name} [${a.sector}] ACTIVE`, 'deploy');
            });
        }
    }

    cmdHelp() {
        const cmds = [
            'deploy <wolf> [target] — Send a wolf',
            'recall <wolf|all>     — Recall wolf(s)',
            'hunt <target>         — Deploy all elites',
            'find <keyword>        — Search wolves',
            'status                — Pack status',
            'stop                  — Recall all',
        ];
        cmds.forEach(c => this.log('', '  ' + c));
    }

    updateStats() {
        document.getElementById('stat-active').textContent = this.activeAgents.size;
        document.getElementById('hud-status-text').textContent = this.activeAgents.size > 0 ? 'HUNTING' : 'STANDBY';
        const beacon = document.getElementById('status-beacon');
        beacon.style.background = this.activeAgents.size > 0 ? '#ff0066' : '#00e5ff';
        beacon.style.boxShadow = this.activeAgents.size > 0 ? '0 0 15px rgba(255,0,102,0.6)' : '0 0 15px rgba(0,229,255,0.4)';
    }

    log(source, message, type) {
        const container = document.getElementById('activity-log');
        const line = document.createElement('div');
        line.className = 'log-line' + (type ? ' ' + type : '');
        const now = new Date();
        const time = now.getHours().toString().padStart(2, '0') + ':' + now.getMinutes().toString().padStart(2, '0') + ':' + now.getSeconds().toString().padStart(2, '0');
        line.innerHTML = `<span class="log-time">${time}</span> ${source ? '<span class="log-wolf">' + source + '</span> ' : ''}${message}`;
        container.appendChild(line);
        container.scrollTop = container.scrollHeight;
        if (container.children.length > 100) container.removeChild(container.firstChild);
    }

    showAgentDetail(agent) {
        this.selectedAgent = agent;
        document.getElementById('intel-content').style.display = 'none';
        document.getElementById('intel-detail').style.display = 'block';
        document.getElementById('intel-dot').style.background = agent.color;
        document.getElementById('intel-dot').style.boxShadow = `0 0 10px ${agent.color}`;
        document.getElementById('intel-name').textContent = agent.display_name;
        document.getElementById('intel-sector').textContent = agent.sector;
        document.getElementById('intel-lines').textContent = agent.lines + ' lines';
        const isActive = this.activeAgents.has(agent.id);
        document.getElementById('intel-status').textContent = isActive ? 'ACTIVE' : 'IDLE';
        document.getElementById('intel-status').style.color = isActive ? '#00ff88' : '#4a4a6a';
        document.getElementById('intel-status').style.borderColor = isActive ? '#00ff8844' : 'var(--border)';
        document.getElementById('intel-quote').textContent = agent.description || 'Awaiting orders...';

        if (agent.exists) {
            fetch('/api/agent/' + agent.name).then(r => r.json()).then(data => {
                document.getElementById('intel-code').textContent =
                    data.content.substring(0, 2000) + (data.content.length > 2000 ? '\n\n... [' + data.lines + ' lines]' : '');
            });
        } else {
            document.getElementById('intel-code').textContent = '[ PLAYBOOK NOT DEPLOYED ]';
        }
    }

    // =====================================================================
    // Render
    // =====================================================================
    animate() {
        this.time += 0.016;
        this.particles.update();
        this.particles.draw();
        this.draw();
        requestAnimationFrame(() => this.animate());
    }

    draw() {
        const ctx = this.ctx;
        ctx.clearRect(0, 0, this.width, this.height);
        ctx.save();
        ctx.translate(0, this.scroll.y);
        ctx.scale(this.zoom, this.zoom);

        this.buildings.forEach(bld => {
            const isHovered = this.hoveredBuilding === bld;
            const hasActive = bld.agents.some(a => this.activeAgents.has(a.id));

            // Building background
            ctx.fillStyle = isHovered ? 'rgba(20, 15, 50, 0.9)' : 'rgba(10, 10, 25, 0.8)';
            ctx.strokeStyle = hasActive ? bld.color + 'aa' : bld.color + '33';
            ctx.lineWidth = hasActive ? 1.5 : 1;

            // Rounded rect
            this.roundRect(ctx, bld.x, bld.y, bld.w, bld.h, 8);
            ctx.fill();
            ctx.stroke();

            // Top accent line
            ctx.fillStyle = bld.color;
            ctx.fillRect(bld.x + 1, bld.y + 1, bld.w - 2, 3);

            // Building glow for active sectors
            if (hasActive) {
                ctx.shadowColor = bld.color;
                ctx.shadowBlur = 20;
                ctx.strokeStyle = bld.color + '60';
                this.roundRect(ctx, bld.x, bld.y, bld.w, bld.h, 8);
                ctx.stroke();
                ctx.shadowBlur = 0;
            }

            // Building name
            ctx.fillStyle = bld.color;
            ctx.font = "bold 11px 'Orbitron', sans-serif";
            ctx.textAlign = 'left';
            ctx.fillText(bld.name.toUpperCase(), bld.x + 10, bld.y + 22);

            // Wolf count
            ctx.fillStyle = '#4a4a6a';
            ctx.font = "10px 'JetBrains Mono', monospace";
            ctx.textAlign = 'right';
            const activeInSector = bld.agents.filter(a => this.activeAgents.has(a.id)).length;
            const countText = activeInSector > 0 ? `${activeInSector}/${bld.agents.length}` : `${bld.agents.length}`;
            ctx.fillText(countText + ' wolves', bld.x + bld.w - 10, bld.y + 22);

            // Level indicator
            ctx.fillStyle = bld.color + '44';
            ctx.font = "bold 9px 'Orbitron', sans-serif";
            ctx.textAlign = 'right';
            ctx.fillText('LV.' + Math.min(Math.ceil(bld.agents.length / 5), 10), bld.x + bld.w - 10, bld.y + 36);

            // Separator line
            ctx.strokeStyle = bld.color + '22';
            ctx.lineWidth = 0.5;
            ctx.beginPath();
            ctx.moveTo(bld.x + 10, bld.y + 42);
            ctx.lineTo(bld.x + bld.w - 10, bld.y + 42);
            ctx.stroke();

            // Draw wolves inside building
            bld.agents.forEach(agent => {
                const isActive = this.activeAgents.has(agent.id);
                const isSelected = this.selectedAgent && this.selectedAgent.id === agent.id;
                const isHov = this.hoveredAgent && this.hoveredAgent.id === agent.id;
                const pulse = Math.sin(this.time * 3 + agent.phase) * 0.3 + 0.7;
                const r = agent.radius * (isSelected ? 1.6 : isHov ? 1.3 : 1);

                // Active glow
                if (isActive) {
                    ctx.beginPath();
                    ctx.arc(agent.bx, agent.by, r * 3, 0, Math.PI * 2);
                    const grd = ctx.createRadialGradient(agent.bx, agent.by, 0, agent.bx, agent.by, r * 3);
                    grd.addColorStop(0, agent.color + '50');
                    grd.addColorStop(1, agent.color + '00');
                    ctx.fillStyle = grd;
                    ctx.fill();

                    // Spinning ring
                    ctx.beginPath();
                    ctx.arc(agent.bx, agent.by, r * 2, this.time * 3, this.time * 3 + Math.PI);
                    ctx.strokeStyle = agent.color + '88';
                    ctx.lineWidth = 1;
                    ctx.stroke();
                }

                // Wolf dot
                ctx.beginPath();
                ctx.arc(agent.bx, agent.by, r, 0, Math.PI * 2);
                ctx.fillStyle = agent.color;
                ctx.globalAlpha = isActive ? 1 : pulse * 0.7;
                ctx.fill();
                ctx.globalAlpha = 1;

                // Selection ring
                if (isSelected || isHov) {
                    ctx.beginPath();
                    ctx.arc(agent.bx, agent.by, r + 2.5, 0, Math.PI * 2);
                    ctx.strokeStyle = isSelected ? '#ffffff' : agent.color + '88';
                    ctx.lineWidth = 1;
                    ctx.stroke();
                }
            });
        });

        ctx.restore();
    }

    roundRect(ctx, x, y, w, h, r) {
        ctx.beginPath();
        ctx.moveTo(x + r, y);
        ctx.lineTo(x + w - r, y);
        ctx.quadraticCurveTo(x + w, y, x + w, y + r);
        ctx.lineTo(x + w, y + h - r);
        ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
        ctx.lineTo(x + r, y + h);
        ctx.quadraticCurveTo(x, y + h, x, y + h - r);
        ctx.lineTo(x, y + r);
        ctx.quadraticCurveTo(x, y, x + r, y);
        ctx.closePath();
    }

    getItemAt(mx, my) {
        const x = mx / this.zoom;
        const y = (my - this.scroll.y) / this.zoom;

        // Check wolves first
        for (const agent of this.agents) {
            const dx = agent.bx - x;
            const dy = agent.by - y;
            if (dx * dx + dy * dy < (agent.radius + 5) * (agent.radius + 5)) {
                return { type: 'agent', agent };
            }
        }

        // Check buildings
        for (const bld of this.buildings) {
            if (x >= bld.x && x <= bld.x + bld.w && y >= bld.y && y <= bld.y + bld.h) {
                return { type: 'building', building: bld };
            }
        }

        return null;
    }

    bindEvents() {
        window.addEventListener('resize', () => {
            this.resize();
            this.particles.resize();
            this.layoutBuildings();
        });

        this.canvas.addEventListener('mousemove', (e) => {
            const rect = this.canvas.getBoundingClientRect();
            const mx = e.clientX - rect.left;
            const my = e.clientY - rect.top;

            if (this.isDragging) {
                this.scroll.y += e.movementY;
                this.scroll.y = Math.min(0, Math.max(-(this.contentHeight - this.height + 40), this.scroll.y));
                return;
            }

            const item = this.getItemAt(mx, my);
            this.hoveredAgent = item && item.type === 'agent' ? item.agent : null;
            this.hoveredBuilding = item && item.type === 'building' ? item.building : null;
            this.canvas.style.cursor = item ? 'pointer' : 'default';
        });

        this.canvas.addEventListener('mousedown', (e) => {
            const rect = this.canvas.getBoundingClientRect();
            const item = this.getItemAt(e.clientX - rect.left, e.clientY - rect.top);
            if (item && item.type === 'agent') {
                this.showAgentDetail(item.agent);
                this.log('ALPHA', `Inspecting ${item.agent.display_name}`);
            } else {
                this.isDragging = true;
                this.canvas.style.cursor = 'grabbing';
            }
        });

        this.canvas.addEventListener('mouseup', () => {
            this.isDragging = false;
            this.canvas.style.cursor = 'default';
        });

        this.canvas.addEventListener('wheel', (e) => {
            e.preventDefault();
            this.scroll.y -= e.deltaY;
            this.scroll.y = Math.min(0, Math.max(-(this.contentHeight - this.height + 40), this.scroll.y));
        });

        // Command input with autocomplete
        const cmdInput = document.getElementById('cmd-input');
        this.cmdHistory = [];
        this.cmdHistoryIndex = -1;

        cmdInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && cmdInput.value.trim()) {
                this.cmdHistory.unshift(cmdInput.value.trim());
                this.cmdHistoryIndex = -1;
                this.log('ALPHA', '> ' + cmdInput.value.trim());
                this.executeCommand(cmdInput.value.trim());
                cmdInput.value = '';
                this.hideAutocomplete();
            } else if (e.key === 'Tab') {
                e.preventDefault();
                this.acceptAutocomplete(cmdInput);
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (this.cmdHistoryIndex < this.cmdHistory.length - 1) {
                    this.cmdHistoryIndex++;
                    cmdInput.value = this.cmdHistory[this.cmdHistoryIndex];
                }
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (this.cmdHistoryIndex > 0) {
                    this.cmdHistoryIndex--;
                    cmdInput.value = this.cmdHistory[this.cmdHistoryIndex];
                } else {
                    this.cmdHistoryIndex = -1;
                    cmdInput.value = '';
                }
            } else if (e.key === 'Escape') {
                this.hideAutocomplete();
            }
        });

        cmdInput.addEventListener('input', () => {
            this.showAutocomplete(cmdInput);
        });

        document.addEventListener('keydown', (e) => {
            if (e.target !== cmdInput && !e.ctrlKey && !e.metaKey && e.key.length === 1) {
                cmdInput.focus();
            }
        });

        // Click outside to hide autocomplete
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.command-chain')) this.hideAutocomplete();
        });
    }

    // Autocomplete system
    getCommands() {
        const wolfNames = this.agents.map(a => a.name);
        return {
            commands: [
                { cmd: 'hunt', desc: 'Deploy wolves on a target', usage: 'hunt <target.com>' },
                { cmd: 'deploy', desc: 'Send a specific wolf', usage: 'deploy <wolf-name> [target]' },
                { cmd: 'send', desc: 'Same as deploy', usage: 'send <wolf-name> [target]' },
                { cmd: 'recall', desc: 'Recall a wolf or all', usage: 'recall <wolf-name|all>' },
                { cmd: 'stop', desc: 'Recall all wolves', usage: 'stop' },
                { cmd: 'status', desc: 'Show pack status', usage: 'status' },
                { cmd: 'find', desc: 'Search for wolves', usage: 'find <keyword>' },
                { cmd: 'help', desc: 'Show all commands', usage: 'help' },
                { cmd: 'clear', desc: 'Clear activity log', usage: 'clear' },
            ],
            wolves: wolfNames,
        };
    }

    showAutocomplete(input) {
        const val = input.value.trim().toLowerCase();
        if (!val) { this.hideAutocomplete(); return; }

        let suggestions = [];
        const parts = val.split(/\s+/);
        const { commands, wolves } = this.getCommands();

        if (parts.length === 1) {
            // Suggest commands
            suggestions = commands.filter(c => c.cmd.startsWith(parts[0]))
                .map(c => ({ text: c.cmd, desc: c.desc, usage: c.usage, type: 'cmd' }));
        } else if (parts.length === 2 && ['deploy', 'send', 'recall'].includes(parts[0])) {
            // Suggest wolf names
            const query = parts[1];
            suggestions = wolves.filter(w => w.includes(query))
                .slice(0, 8)
                .map(w => {
                    const agent = this.agents.find(a => a.name === w);
                    return { text: parts[0] + ' ' + w, desc: agent ? agent.sector : '', type: 'wolf' };
                });
        }

        if (suggestions.length === 0) { this.hideAutocomplete(); return; }

        let dropdown = document.getElementById('cmd-autocomplete');
        if (!dropdown) {
            dropdown = document.createElement('div');
            dropdown.id = 'cmd-autocomplete';
            dropdown.className = 'cmd-autocomplete';
            document.querySelector('.command-chain').appendChild(dropdown);
        }

        dropdown.innerHTML = suggestions.map((s, i) => `
            <div class="autocomplete-item${i === 0 ? ' active' : ''}" data-value="${s.text}">
                <span class="ac-text">${s.text}</span>
                <span class="ac-desc">${s.desc || ''}</span>
                ${s.usage ? '<span class="ac-usage">' + s.usage + '</span>' : ''}
            </div>
        `).join('');

        dropdown.style.display = 'block';
        this.currentSuggestions = suggestions;

        // Click to select
        dropdown.querySelectorAll('.autocomplete-item').forEach(item => {
            item.addEventListener('click', () => {
                input.value = item.dataset.value + ' ';
                input.focus();
                this.hideAutocomplete();
            });
        });
    }

    acceptAutocomplete(input) {
        const dropdown = document.getElementById('cmd-autocomplete');
        if (!dropdown || dropdown.style.display === 'none') return;
        const active = dropdown.querySelector('.autocomplete-item.active');
        if (active) {
            input.value = active.dataset.value + ' ';
            this.hideAutocomplete();
        }
    }

    hideAutocomplete() {
        const dropdown = document.getElementById('cmd-autocomplete');
        if (dropdown) dropdown.style.display = 'none';
    }

    // Tab switching
    showTab(tab) {
        document.getElementById('tab-wolf').classList.toggle('active', tab === 'wolf');
        document.getElementById('tab-findings').classList.toggle('active', tab === 'findings');

        document.getElementById('intel-content').style.display = tab === 'wolf' ? 'block' : 'none';
        document.getElementById('intel-detail').style.display = 'none';
        document.getElementById('findings-panel').style.display = tab === 'findings' ? 'block' : 'none';
    }

    // Findings polling
    startAutoPolling() {
        // Check for CLI-pushed findings every 2 seconds
        setInterval(() => {
            fetch('/api/findings').then(r => r.json()).then(data => {
                if (data.count > 0 && data.count !== this._lastAutoCount) {
                    this._lastAutoCount = data.count;
                    document.getElementById('findings-badge').textContent = data.count;
                    document.getElementById('stat-findings').textContent = data.count;

                    // If not already polling, start showing findings
                    if (!this.findingsInterval) {
                        this.showTab('findings');
                        this.startFindingsPolling();
                    }
                }
            }).catch(() => {});
        }, 2000);
        this._lastAutoCount = 0;
    }

    startFindingsPolling() {
        if (this.findingsInterval) clearInterval(this.findingsInterval);
        this.lastFindingCount = 0;

        this.findingsInterval = setInterval(() => {
            fetch('/api/findings').then(r => r.json()).then(data => {
                document.getElementById('findings-target').textContent = data.target;
                document.getElementById('findings-count').textContent = data.count + ' findings';
                document.getElementById('findings-badge').textContent = data.count;
                document.getElementById('stat-findings').textContent = data.count;

                // Render new findings
                if (data.count > this.lastFindingCount) {
                    const list = document.getElementById('findings-list');
                    const newFindings = data.findings.slice(this.lastFindingCount);

                    newFindings.forEach(f => {
                        const item = document.createElement('div');
                        item.className = 'finding-item';

                        // Color based on wolf
                        const wolfColors = {
                            'Shadow Recon': '#ff0040',
                            'Tech Stack Detector': '#00e5ff',
                            'Recon Master': '#00ff88',
                            'Network Mapper': '#44aaff',
                            'ALPHA': '#ff0066',
                        };
                        const color = wolfColors[f.wolf] || '#9c27ff';

                        item.innerHTML = `
                            <span class="finding-time">${f.time}</span>
                            <div class="finding-wolf" style="color:${color}">${f.wolf}</div>
                            <div class="finding-category">${f.category}</div>
                            <div class="finding-data">${f.data}</div>
                        `;
                        list.appendChild(item);

                        // Log it too
                        if (f.wolf !== 'ALPHA') {
                            this.log(f.wolf, `${f.category}: ${f.data}`, f.category === 'Error' ? 'alert' : 'finding');
                        }
                    });

                    list.scrollTop = list.scrollHeight;
                    this.lastFindingCount = data.count;
                }

                // Stop polling when hunt is done
                if (!data.active && data.count > 0 && data.count === this.lastFindingCount) {
                    clearInterval(this.findingsInterval);
                    this.findingsInterval = null;
                    this.log('ALPHA', `Hunt complete. ${data.count} findings collected.`, 'finding');
                    this.updateStats();
                }
            });
        }, 1000);
    }
}

// Init
document.addEventListener('DOMContentLoaded', () => { window.wolfDen = new WolfDen(); });
