const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { execSync, exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.CLAUDEOS_PORT || 8080;
const CLAUDEOS_DIR = process.env.CLAUDEOS_DIR || '/opt/claudeos';

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Helper to run commands safely
function runCmd(cmd, timeout = 10000) {
    try {
        return execSync(cmd, { timeout, encoding: 'utf-8' }).trim();
    } catch (e) {
        return e.stdout ? e.stdout.trim() : 'Error: ' + e.message;
    }
}

// API: System info
app.get('/api/system', (req, res) => {
    const loadAvg = os.loadavg();
    const cpus = os.cpus().length;
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;

    const diskOutput = runCmd("df -B1 / | awk 'NR==2{print $2,$3,$4,$5}'");
    const diskParts = diskOutput.split(' ');

    res.json({
        hostname: os.hostname(),
        platform: runCmd('cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d \\"'),
        kernel: os.release(),
        uptime: os.uptime(),
        cpu: {
            cores: cpus,
            load1: loadAvg[0],
            load5: loadAvg[1],
            load15: loadAvg[2],
            percent: Math.round((loadAvg[0] / cpus) * 100)
        },
        memory: {
            total: totalMem,
            used: usedMem,
            free: freeMem,
            percent: Math.round((usedMem / totalMem) * 100)
        },
        disk: {
            total: parseInt(diskParts[0]) || 0,
            used: parseInt(diskParts[1]) || 0,
            free: parseInt(diskParts[2]) || 0,
            percent: parseInt(diskParts[3]) || 0
        }
    });
});

// API: Services
app.get('/api/services', (req, res) => {
    const services = ['nginx', 'apache2', 'mysql', 'mariadb', 'postgresql', 'php8.1-fpm', 'php8.2-fpm', 'php8.3-fpm', 'php8.4-fpm', 'docker', 'ssh', 'ufw', 'fail2ban', 'cron'];
    const result = services.map(svc => {
        const active = runCmd(`systemctl is-active ${svc} 2>/dev/null`) === 'active';
        const exists = runCmd(`systemctl list-unit-files ${svc}.service 2>/dev/null | grep -c ${svc}`) !== '0';
        return { name: svc, active, exists };
    }).filter(s => s.exists);
    res.json(result);
});

// API: Security
app.get('/api/security', (req, res) => {
    const ufwActive = runCmd('ufw status 2>/dev/null | head -1').includes('active');
    const fail2banActive = runCmd('systemctl is-active fail2ban 2>/dev/null') === 'active';
    const bannedIPs = parseInt(runCmd("fail2ban-client status sshd 2>/dev/null | grep 'Currently banned' | awk '{print $NF}'")) || 0;
    const failedSSH = parseInt(runCmd(`grep "Failed password" /var/log/auth.log 2>/dev/null | grep "$(date +%Y-%m-%d)" | wc -l`)) || 0;
    const ufwRules = runCmd('ufw status numbered 2>/dev/null | grep -c "\\["') || '0';

    res.json({
        firewall: { active: ufwActive, rules: parseInt(ufwRules) },
        fail2ban: { active: fail2banActive, banned: bannedIPs },
        failedSSH: failedSSH
    });
});

// API: Processes (top 10 by CPU)
app.get('/api/processes', (req, res) => {
    const output = runCmd("ps aux --sort=-%cpu | head -11 | tail -10");
    const procs = output.split('\n').map(line => {
        const parts = line.trim().split(/\s+/);
        return {
            user: parts[0],
            pid: parts[1],
            cpu: parseFloat(parts[2]),
            mem: parseFloat(parts[3]),
            command: parts.slice(10).join(' ')
        };
    });
    res.json(procs);
});

// API: Recent logs
app.get('/api/logs', (req, res) => {
    const logDir = path.join(CLAUDEOS_DIR, 'logs');
    let entries = [];

    try {
        const files = fs.readdirSync(logDir).filter(f => f.endsWith('.log'));
        files.forEach(file => {
            const content = fs.readFileSync(path.join(logDir, file), 'utf-8');
            const lines = content.split('\n').filter(l => l.trim());
            entries = entries.concat(lines.slice(-20));
        });
    } catch (e) {}

    entries.sort();
    res.json(entries.slice(-30));
});

// API: Alerts
app.get('/api/alerts', (req, res) => {
    const logDir = path.join(CLAUDEOS_DIR, 'logs');
    let alerts = [];

    try {
        const files = fs.readdirSync(logDir).filter(f => f.endsWith('.log'));
        files.forEach(file => {
            const content = fs.readFileSync(path.join(logDir, file), 'utf-8');
            const lines = content.split('\n').filter(l =>
                l.includes('[WARNING]') || l.includes('[CRITICAL]') || l.includes('[ALERT]')
            );
            alerts = alerts.concat(lines);
        });
    } catch (e) {}

    alerts.sort().reverse();
    res.json(alerts.slice(0, 20));
});

// API: Backups
app.get('/api/backups', (req, res) => {
    try {
        const files = fs.readdirSync('/backups').map(f => {
            const stats = fs.statSync(path.join('/backups', f));
            return { name: f, size: stats.size, date: stats.mtime };
        });
        files.sort((a, b) => b.date - a.date);
        res.json(files);
    } catch (e) {
        res.json([]);
    }
});

// API: Quick actions
app.post('/api/action/:action', (req, res) => {
    const actions = {
        'backup': `bash ${CLAUDEOS_DIR}/scripts/auto-backup.sh`,
        'health': `bash ${CLAUDEOS_DIR}/scripts/auto-health.sh`,
        'security': `bash ${CLAUDEOS_DIR}/scripts/auto-security.sh`,
        'update': 'apt update -qq && apt list --upgradable 2>/dev/null',
        'report': `bash ${CLAUDEOS_DIR}/scripts/daily-report.sh`,
        'optimize': `bash ${CLAUDEOS_DIR}/scripts/auto-optimize.sh`
    };

    const cmd = actions[req.params.action];
    if (!cmd) return res.status(400).json({ error: 'Unknown action' });

    exec(cmd, { timeout: 60000 }, (error, stdout, stderr) => {
        res.json({ success: !error, output: stdout || stderr || 'Done' });
    });
});

// API: Service control
app.post('/api/service/:name/:action', (req, res) => {
    const { name, action } = req.params;
    const allowed = ['start', 'stop', 'restart'];
    if (!allowed.includes(action)) return res.status(400).json({ error: 'Invalid action' });

    exec(`systemctl ${action} ${name}`, { timeout: 15000 }, (error, stdout, stderr) => {
        const active = runCmd(`systemctl is-active ${name} 2>/dev/null`) === 'active';
        res.json({ success: !error, active, output: stdout || stderr });
    });
});

// WebSocket for real-time updates
wss.on('connection', (ws) => {
    const interval = setInterval(() => {
        const loadAvg = os.loadavg();
        const cpus = os.cpus().length;
        const totalMem = os.totalmem();
        const freeMem = os.freemem();

        ws.send(JSON.stringify({
            type: 'stats',
            cpu: Math.round((loadAvg[0] / cpus) * 100),
            memory: Math.round(((totalMem - freeMem) / totalMem) * 100),
            load: loadAvg[0],
            time: Date.now()
        }));
    }, 3000);

    ws.on('close', () => clearInterval(interval));
});

// Serve dashboard
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n  ClaudeOS Dashboard running at http://0.0.0.0:${PORT}\n`);
});
