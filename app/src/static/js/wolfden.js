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
        // Embedded agent data — works in Tauri, browser, and server mode
        let data = null;
        try {
            const resp = await fetch('/api/agents');
            if (resp.ok) data = await resp.json();
        } catch(e) {}
        if (!data) data = [{"color":"#ff0040","description":"A shadow leaves no footprint, makes no sound, but sees everything.","display_name":"Shadow Recon","exists":true,"id":0,"lines":505,"name":"shadow-recon","sector":"Elite Wolves","status":"idle"},{"color":"#ff0040","description":"Every door was built to be opened. The lock is just a riddle \u2014 and I solve riddles.","display_name":"Phantom Auth","exists":true,"id":1,"lines":1122,"name":"phantom-auth","sector":"Elite Wolves","status":"idle"},{"color":"#ff0040","description":"Source code doesn't lie. It confesses everything \u2014 you just have to know where to press.","display_name":"Code Weaponizer","exists":true,"id":2,"lines":1116,"name":"code-weaponizer","sector":"Elite Wolves","status":"idle"},{"color":"#ff0040","description":"One crack in the wall is informational. Three cracks in the right places bring down the building.","display_name":"Chain Builder","exists":true,"id":3,"lines":952,"name":"chain-builder","sector":"Elite Wolves","status":"idle"},{"color":"#ff0040","description":"The most dangerous systems are the ones nobody remembers exist.","display_name":"Time Traveler","exists":true,"id":4,"lines":1018,"name":"time-traveler","sector":"Elite Wolves","status":"idle"},{"color":"#ff0040","description":"Follow the money. Every payment flow has a moment where trust replaces verification \u2014 that's where you strike.","display_name":"Wallet Breaker","exists":true,"id":5,"lines":1321,"name":"wallet-breaker","sector":"Elite Wolves","status":"idle"},{"color":"#00d4ff","description":"","display_name":"Incident Responder","exists":true,"id":6,"lines":462,"name":"incident-responder","sector":"Intelligence","status":"idle"},{"color":"#00d4ff","description":"","display_name":"Performance Tuner","exists":true,"id":7,"lines":617,"name":"performance-tuner","sector":"Intelligence","status":"idle"},{"color":"#00d4ff","description":"","display_name":"Cost Optimizer","exists":true,"id":8,"lines":400,"name":"cost-optimizer","sector":"Intelligence","status":"idle"},{"color":"#00d4ff","description":"","display_name":"Migration","exists":true,"id":9,"lines":713,"name":"migration","sector":"Intelligence","status":"idle"},{"color":"#00d4ff","description":"","display_name":"Threat Intel","exists":true,"id":10,"lines":593,"name":"threat-intel","sector":"Intelligence","status":"idle"},{"color":"#00ff88","description":"","display_name":"Subdomain Bruteforcer","exists":true,"id":11,"lines":404,"name":"subdomain-bruteforcer","sector":"Scouts","status":"idle"},{"color":"#00ff88","description":"","display_name":"Tech Stack Detector","exists":true,"id":12,"lines":415,"name":"tech-stack-detector","sector":"Scouts","status":"idle"},{"color":"#00ff88","description":"","display_name":"Dns Manager","exists":true,"id":13,"lines":574,"name":"dns-manager","sector":"Scouts","status":"idle"},{"color":"#00ff88","description":"","display_name":"Osint Gatherer","exists":true,"id":14,"lines":753,"name":"osint-gatherer","sector":"Scouts","status":"idle"},{"color":"#00ff88","description":"","display_name":"Github Recon","exists":true,"id":15,"lines":634,"name":"github-recon","sector":"Scouts","status":"idle"},{"color":"#00ff88","description":"","display_name":"Shodan Pivoter","exists":true,"id":16,"lines":510,"name":"shodan-pivoter","sector":"Scouts","status":"idle"},{"color":"#00ff88","description":"","display_name":"S3 Bucket Finder","exists":true,"id":17,"lines":500,"name":"s3-bucket-finder","sector":"Scouts","status":"idle"},{"color":"#00ff88","description":"","display_name":"Cloud Recon","exists":true,"id":18,"lines":925,"name":"cloud-recon","sector":"Scouts","status":"idle"},{"color":"#00ff88","description":"","display_name":"Recon Master","exists":true,"id":19,"lines":962,"name":"recon-master","sector":"Scouts","status":"idle"},{"color":"#00ff88","description":"","display_name":"Recon Orchestrator","exists":true,"id":20,"lines":537,"name":"recon-orchestrator","sector":"Scouts","status":"idle"},{"color":"#00ff88","description":"","display_name":"Screenshot Hunter","exists":true,"id":21,"lines":389,"name":"screenshot-hunter","sector":"Scouts","status":"idle"},{"color":"#ffaa00","description":"","display_name":"Js Endpoint Extractor","exists":true,"id":22,"lines":159,"name":"js-endpoint-extractor","sector":"Infiltrators","status":"idle"},{"color":"#ffaa00","description":"","display_name":"Js Analyzer","exists":true,"id":23,"lines":549,"name":"js-analyzer","sector":"Infiltrators","status":"idle"},{"color":"#ffaa00","description":"","display_name":"Sourcemap Extractor","exists":true,"id":24,"lines":263,"name":"sourcemap-extractor","sector":"Infiltrators","status":"idle"},{"color":"#ffaa00","description":"","display_name":"Config Extractor","exists":true,"id":25,"lines":340,"name":"config-extractor","sector":"Infiltrators","status":"idle"},{"color":"#ffaa00","description":"","display_name":"Swagger Extractor","exists":true,"id":26,"lines":354,"name":"swagger-extractor","sector":"Infiltrators","status":"idle"},{"color":"#ffaa00","description":"","display_name":"Git Extractor","exists":true,"id":27,"lines":302,"name":"git-extractor","sector":"Infiltrators","status":"idle"},{"color":"#ffaa00","description":"","display_name":"Metadata Extractor","exists":true,"id":28,"lines":313,"name":"metadata-extractor","sector":"Infiltrators","status":"idle"},{"color":"#ffaa00","description":"","display_name":"Apk Extractor","exists":true,"id":29,"lines":302,"name":"apk-extractor","sector":"Infiltrators","status":"idle"},{"color":"#ffaa00","description":"","display_name":"Error Extractor","exists":true,"id":30,"lines":332,"name":"error-extractor","sector":"Infiltrators","status":"idle"},{"color":"#ffaa00","description":"","display_name":"Headless Browser","exists":true,"id":31,"lines":491,"name":"headless-browser","sector":"Infiltrators","status":"idle"},{"color":"#aa44ff","description":"","display_name":"Waf Fingerprinter","exists":true,"id":32,"lines":508,"name":"waf-fingerprinter","sector":"Analysts","status":"idle"},{"color":"#aa44ff","description":"","display_name":"Waf Rule Analyzer","exists":true,"id":33,"lines":445,"name":"waf-rule-analyzer","sector":"Analysts","status":"idle"},{"color":"#aa44ff","description":"","display_name":"Waf Bypass Scanner","exists":true,"id":34,"lines":536,"name":"waf-bypass-scanner","sector":"Analysts","status":"idle"},{"color":"#aa44ff","description":"","display_name":"Waf Cloudflare Bypass","exists":true,"id":35,"lines":621,"name":"waf-cloudflare-bypass","sector":"Analysts","status":"idle"},{"color":"#aa44ff","description":"","display_name":"Waf Akamai Bypass","exists":true,"id":36,"lines":679,"name":"waf-akamai-bypass","sector":"Analysts","status":"idle"},{"color":"#aa44ff","description":"","display_name":"Waf Aws Bypass","exists":true,"id":37,"lines":263,"name":"waf-aws-bypass","sector":"Analysts","status":"idle"},{"color":"#aa44ff","description":"","display_name":"Waf Modsecurity Bypass","exists":true,"id":38,"lines":245,"name":"waf-modsecurity-bypass","sector":"Analysts","status":"idle"},{"color":"#aa44ff","description":"","display_name":"Waf Imperva Bypass","exists":true,"id":39,"lines":285,"name":"waf-imperva-bypass","sector":"Analysts","status":"idle"},{"color":"#aa44ff","description":"","display_name":"Waf Custom Bypass","exists":true,"id":40,"lines":309,"name":"waf-custom-bypass","sector":"Analysts","status":"idle"},{"color":"#aa44ff","description":"","display_name":"Waf Payload Encoder","exists":true,"id":41,"lines":449,"name":"waf-payload-encoder","sector":"Analysts","status":"idle"},{"color":"#aa44ff","description":"","display_name":"Waf Protocol Bypass","exists":true,"id":42,"lines":451,"name":"waf-protocol-bypass","sector":"Analysts","status":"idle"},{"color":"#aa44ff","description":"","display_name":"Token Analyzer","exists":true,"id":43,"lines":446,"name":"token-analyzer","sector":"Analysts","status":"idle"},{"color":"#aa44ff","description":"","display_name":"Cookie Security Auditor","exists":true,"id":44,"lines":357,"name":"cookie-security-auditor","sector":"Analysts","status":"idle"},{"color":"#aa44ff","description":"","display_name":"Csp Analyzer","exists":true,"id":45,"lines":546,"name":"csp-analyzer","sector":"Analysts","status":"idle"},{"color":"#ff4444","description":"","display_name":"Xss Hunter","exists":true,"id":46,"lines":936,"name":"xss-hunter","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Sqli Hunter","exists":true,"id":47,"lines":947,"name":"sqli-hunter","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Ssrf Hunter","exists":true,"id":48,"lines":1063,"name":"ssrf-hunter","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Idor Hunter","exists":true,"id":49,"lines":828,"name":"idor-hunter","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Cors Tester","exists":true,"id":50,"lines":607,"name":"cors-tester","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Cors Chain Analyzer","exists":true,"id":51,"lines":280,"name":"cors-chain-analyzer","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Graphql Hunter","exists":true,"id":52,"lines":730,"name":"graphql-hunter","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Jwt Hunter","exists":true,"id":53,"lines":799,"name":"jwt-hunter","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Xxe Hunter","exists":true,"id":54,"lines":514,"name":"xxe-hunter","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Ssti Hunter","exists":true,"id":55,"lines":435,"name":"ssti-hunter","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Lfi Hunter","exists":true,"id":56,"lines":450,"name":"lfi-hunter","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Csrf Hunter","exists":true,"id":57,"lines":463,"name":"csrf-hunter","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Request Smuggler","exists":true,"id":58,"lines":393,"name":"request-smuggler","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Race Hunter","exists":true,"id":59,"lines":410,"name":"race-hunter","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Cache Poisoner","exists":true,"id":60,"lines":377,"name":"cache-poisoner","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Prototype Pollution Hunter","exists":true,"id":61,"lines":437,"name":"prototype-pollution-hunter","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Oauth Tester","exists":true,"id":62,"lines":659,"name":"oauth-tester","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Saml Tester","exists":true,"id":63,"lines":536,"name":"saml-tester","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Deserialization Hunter","exists":true,"id":64,"lines":458,"name":"deserialization-hunter","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Blind Injection Tester","exists":true,"id":65,"lines":493,"name":"blind-injection-tester","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Param Finder","exists":true,"id":66,"lines":389,"name":"param-finder","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Websocket Tester","exists":true,"id":67,"lines":531,"name":"websocket-tester","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Postmessage Abuser","exists":true,"id":68,"lines":567,"name":"postmessage-abuser","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Account Takeover Hunter","exists":true,"id":69,"lines":126,"name":"account-takeover-hunter","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Password Reset Tester","exists":true,"id":70,"lines":318,"name":"password-reset-tester","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"","display_name":"Ecommerce Hunter","exists":true,"id":71,"lines":166,"name":"ecommerce-hunter","sector":"Strikers","status":"idle"},{"color":"#ff4444","description":"**Battle-tested:** These techniques are proven from real bug bounty hunts -- Bumba Exchange order bypass (placed live market orders despite `canTrade:false`), 1win OTP brute-force (4-digit code, no rate limiting), Banco Plata unauthenticated OTP generation, and OPPO Fuxi config center access. Every technique below has drawn blood.","display_name":"Business Logic Hunter","exists":true,"id":72,"lines":1505,"name":"business-logic-hunter","sector":"Strikers","status":"idle"},{"color":"#44aaff","description":"","display_name":"Network Mapper","exists":true,"id":73,"lines":478,"name":"network-mapper","sector":"Infrastructure","status":"idle"},{"color":"#44aaff","description":"","display_name":"Ssl Tester","exists":true,"id":74,"lines":517,"name":"ssl-tester","sector":"Infrastructure","status":"idle"},{"color":"#44aaff","description":"","display_name":"Vulnerability Scanner","exists":true,"id":75,"lines":462,"name":"vulnerability-scanner","sector":"Infrastructure","status":"idle"},{"color":"#44aaff","description":"","display_name":"Cdn Bypass","exists":true,"id":76,"lines":236,"name":"cdn-bypass","sector":"Infrastructure","status":"idle"},{"color":"#44aaff","description":"$OUT/confirmed.txt","display_name":"Origin Finder","exists":true,"id":77,"lines":541,"name":"origin-finder","sector":"Infrastructure","status":"idle"},{"color":"#44aaff","description":"","display_name":"Docker Manager","exists":true,"id":78,"lines":395,"name":"docker-manager","sector":"Infrastructure","status":"idle"},{"color":"#44aaff","description":"","display_name":"Kubernetes Tester","exists":true,"id":79,"lines":586,"name":"kubernetes-tester","sector":"Infrastructure","status":"idle"},{"color":"#44aaff","description":"","display_name":"Container Escape","exists":true,"id":80,"lines":638,"name":"container-escape","sector":"Infrastructure","status":"idle"},{"color":"#44aaff","description":"","display_name":"Aws Tester","exists":true,"id":81,"lines":681,"name":"aws-tester","sector":"Infrastructure","status":"idle"},{"color":"#888888","description":"","display_name":"Evasion Engine","exists":true,"id":82,"lines":910,"name":"evasion-engine","sector":"Stealth & Support","status":"idle"},{"color":"#888888","description":"","display_name":"Proxy Rotator","exists":true,"id":83,"lines":441,"name":"proxy-rotator","sector":"Stealth & Support","status":"idle"},{"color":"#888888","description":"","display_name":"Poc Recorder","exists":true,"id":84,"lines":551,"name":"poc-recorder","sector":"Stealth & Support","status":"idle"},{"color":"#888888","description":"","display_name":"Bounty Report Writer","exists":true,"id":85,"lines":357,"name":"bounty-report-writer","sector":"Stealth & Support","status":"idle"},{"color":"#888888","description":"","display_name":"Nuclei Template Builder","exists":true,"id":86,"lines":557,"name":"nuclei-template-builder","sector":"Stealth & Support","status":"idle"},{"color":"#888888","description":"","display_name":"Nuclei Master","exists":true,"id":87,"lines":586,"name":"nuclei-master","sector":"Stealth & Support","status":"idle"},{"color":"#888888","description":"","display_name":"Response Differ","exists":true,"id":88,"lines":433,"name":"response-differ","sector":"Stealth & Support","status":"idle"},{"color":"#888888","description":"","display_name":"Collaborator","exists":true,"id":89,"lines":465,"name":"collaborator","sector":"Stealth & Support","status":"idle"},{"color":"#888888","description":"","display_name":"Payload Crafter","exists":true,"id":90,"lines":585,"name":"payload-crafter","sector":"Stealth & Support","status":"idle"},{"color":"#888888","description":"","display_name":"Tool Forge","exists":true,"id":91,"lines":867,"name":"tool-forge","sector":"Stealth & Support","status":"idle"},{"color":"#ff2200","description":"","display_name":"Red Commander","exists":true,"id":92,"lines":884,"name":"red-commander","sector":"Red Team","status":"idle"},{"color":"#ff2200","description":"","display_name":"Attack Planner","exists":true,"id":93,"lines":844,"name":"attack-planner","sector":"Red Team","status":"idle"},{"color":"#ff2200","description":"","display_name":"Defense Breaker","exists":true,"id":94,"lines":628,"name":"defense-breaker","sector":"Red Team","status":"idle"},{"color":"#ff2200","description":"","display_name":"Persistence Agent","exists":true,"id":95,"lines":674,"name":"persistence-agent","sector":"Red Team","status":"idle"},{"color":"#ff2200","description":"","display_name":"Lateral Mover","exists":true,"id":96,"lines":510,"name":"lateral-mover","sector":"Red Team","status":"idle"},{"color":"#ff2200","description":"","display_name":"Exfil Operator","exists":true,"id":97,"lines":613,"name":"exfil-operator","sector":"Red Team","status":"idle"},{"color":"#ff2200","description":"","display_name":"Implant Builder","exists":true,"id":98,"lines":784,"name":"implant-builder","sector":"Red Team","status":"idle"},{"color":"#ff2200","description":"","display_name":"Vuln Weaponizer","exists":true,"id":99,"lines":627,"name":"vuln-weaponizer","sector":"Red Team","status":"idle"},{"color":"#ff2200","description":"","display_name":"Phishing Operator","exists":true,"id":100,"lines":618,"name":"phishing-operator","sector":"Red Team","status":"idle"},{"color":"#ff2200","description":"","display_name":"Arsenal Manager","exists":true,"id":101,"lines":809,"name":"arsenal-manager","sector":"Red Team","status":"idle"},{"color":"#ff2200","description":"","display_name":"Blue Team Tester","exists":true,"id":102,"lines":683,"name":"blue-team-tester","sector":"Red Team","status":"idle"},{"color":"#ff2200","description":"","display_name":"Attack Chain","exists":true,"id":103,"lines":501,"name":"attack-chain","sector":"Red Team","status":"idle"},{"color":"#ff2200","description":"","display_name":"C2 Operator","exists":true,"id":104,"lines":606,"name":"c2-operator","sector":"Red Team","status":"idle"},{"color":"#ff2200","description":"","display_name":"Apt Operator","exists":true,"id":105,"lines":518,"name":"apt-operator","sector":"Red Team","status":"idle"},{"color":"#ff8800","description":"","display_name":"Wordpress Hunter","exists":true,"id":106,"lines":596,"name":"wordpress-hunter","sector":"Platform Hunters","status":"idle"},{"color":"#ff8800","description":"","display_name":"Drupal Hunter","exists":true,"id":107,"lines":548,"name":"drupal-hunter","sector":"Platform Hunters","status":"idle"},{"color":"#ff8800","description":"","display_name":"Magento Hunter","exists":true,"id":108,"lines":613,"name":"magento-hunter","sector":"Platform Hunters","status":"idle"},{"color":"#ff8800","description":"","display_name":"Laravel Hunter","exists":true,"id":109,"lines":594,"name":"laravel-hunter","sector":"Platform Hunters","status":"idle"},{"color":"#ff8800","description":"","display_name":"Django Hunter","exists":true,"id":110,"lines":651,"name":"django-hunter","sector":"Platform Hunters","status":"idle"},{"color":"#ff8800","description":"","display_name":"Shopify Hunter","exists":true,"id":111,"lines":657,"name":"shopify-hunter","sector":"Platform Hunters","status":"idle"},{"color":"#ff8800","description":"","display_name":"Okta Tester","exists":true,"id":112,"lines":741,"name":"okta-tester","sector":"Platform Hunters","status":"idle"},{"color":"#ff8800","description":"","display_name":"M365 Attacker","exists":true,"id":113,"lines":654,"name":"m365-attacker","sector":"Platform Hunters","status":"idle"},{"color":"#ff8800","description":"","display_name":"Stripe Webhook Tester","exists":true,"id":114,"lines":519,"name":"stripe-webhook-tester","sector":"Platform Hunters","status":"idle"},{"color":"#66bb6a","description":"","display_name":"Package Manager","exists":true,"id":115,"lines":87,"name":"package-manager","sector":"Core System","status":"idle"},{"color":"#66bb6a","description":"","display_name":"Service Manager","exists":true,"id":116,"lines":105,"name":"service-manager","sector":"Core System","status":"idle"},{"color":"#66bb6a","description":"","display_name":"Security","exists":true,"id":117,"lines":622,"name":"security","sector":"Core System","status":"idle"},{"color":"#66bb6a","description":"","display_name":"Network","exists":true,"id":118,"lines":614,"name":"network","sector":"Core System","status":"idle"},{"color":"#66bb6a","description":"","display_name":"Monitoring","exists":true,"id":119,"lines":513,"name":"monitoring","sector":"Core System","status":"idle"},{"color":"#66bb6a","description":"","display_name":"Backup","exists":true,"id":120,"lines":627,"name":"backup","sector":"Core System","status":"idle"},{"color":"#66bb6a","description":"","display_name":"Cron Tasks","exists":true,"id":121,"lines":350,"name":"cron-tasks","sector":"Core System","status":"idle"},{"color":"#66bb6a","description":"","display_name":"User Manager","exists":true,"id":122,"lines":598,"name":"user-manager","sector":"Core System","status":"idle"},{"color":"#66bb6a","description":"","display_name":"Auto Pilot","exists":true,"id":123,"lines":122,"name":"auto-pilot","sector":"Core System","status":"idle"},{"color":"#66bb6a","description":"","display_name":"Web Server","exists":true,"id":124,"lines":654,"name":"web-server","sector":"Core System","status":"idle"},{"color":"#66bb6a","description":"","display_name":"Database","exists":true,"id":125,"lines":642,"name":"database","sector":"Core System","status":"idle"},{"color":"#66bb6a","description":"","display_name":"Mail Server","exists":true,"id":126,"lines":692,"name":"mail-server","sector":"Core System","status":"idle"},{"color":"#42a5f5","description":"Scaffold projects, boilerplate code, and modules with real working templates and commands.","display_name":"Code Generator","exists":true,"id":127,"lines":1185,"name":"code-generator","sector":"Builders","status":"idle"},{"color":"#42a5f5","description":"","display_name":"Api Builder","exists":true,"id":128,"lines":1053,"name":"api-builder","sector":"Builders","status":"idle"},{"color":"#42a5f5","description":"Design RESTful and GraphQL APIs with proper documentation, authentication, and best practices.","display_name":"Api Designer","exists":true,"id":129,"lines":987,"name":"api-designer","sector":"Builders","status":"idle"},{"color":"#42a5f5","description":"Schema design, migrations, query optimization, and database management with real tools.","display_name":"Database Designer","exists":true,"id":130,"lines":710,"name":"database-designer","sector":"Builders","status":"idle"},{"color":"#42a5f5","description":"Auto-generate unit, integration, and end-to-end tests with real testing frameworks and coverage tools.","display_name":"Test Writer","exists":true,"id":131,"lines":851,"name":"test-writer","sector":"Builders","status":"idle"},{"color":"#42a5f5","description":"Auto-generated documentation. Last updated: TIMESTAMP","display_name":"Documentation","exists":true,"id":132,"lines":1270,"name":"documentation","sector":"Builders","status":"idle"},{"color":"#42a5f5","description":"","display_name":"Git Deploy","exists":true,"id":133,"lines":273,"name":"git-deploy","sector":"Builders","status":"idle"},{"color":"#42a5f5","description":"","display_name":"Pipeline Builder","exists":true,"id":134,"lines":1056,"name":"pipeline-builder","sector":"Builders","status":"idle"},{"color":"#42a5f5","description":"","display_name":"Agent Architect","exists":true,"id":135,"lines":222,"name":"agent-architect","sector":"Builders","status":"idle"},{"color":"#42a5f5","description":"","display_name":"Technique Inventor","exists":true,"id":136,"lines":518,"name":"technique-inventor","sector":"Builders","status":"idle"},{"color":"#42a5f5","description":"","display_name":"Capability Scanner","exists":true,"id":137,"lines":177,"name":"capability-scanner","sector":"Builders","status":"idle"},{"color":"#26c6da","description":"","display_name":"Ddos Shield","exists":true,"id":138,"lines":1590,"name":"ddos-shield","sector":"Defense","status":"idle"},{"color":"#26c6da","description":"","display_name":"Defense Monitor","exists":true,"id":139,"lines":331,"name":"defense-monitor","sector":"Defense","status":"idle"},{"color":"#26c6da","description":"","display_name":"Firewall Visualizer","exists":true,"id":140,"lines":1138,"name":"firewall-visualizer","sector":"Defense","status":"idle"},{"color":"#26c6da","description":"","display_name":"Security Auditor","exists":true,"id":141,"lines":444,"name":"security-auditor","sector":"Defense","status":"idle"},{"color":"#26c6da","description":"","display_name":"Config Hardener","exists":true,"id":142,"lines":618,"name":"config-hardener","sector":"Defense","status":"idle"},{"color":"#26c6da","description":"","display_name":"Access Auditor","exists":true,"id":143,"lines":451,"name":"access-auditor","sector":"Defense","status":"idle"},{"color":"#26c6da","description":"","display_name":"Encryption Enforcer","exists":true,"id":144,"lines":497,"name":"encryption-enforcer","sector":"Defense","status":"idle"},{"color":"#26c6da","description":"","display_name":"Compliance","exists":true,"id":145,"lines":874,"name":"compliance","sector":"Defense","status":"idle"},{"color":"#26c6da","description":"","display_name":"Compliance Checker","exists":true,"id":146,"lines":449,"name":"compliance-checker","sector":"Defense","status":"idle"},{"color":"#26c6da","description":"","display_name":"Honeypot Manager","exists":true,"id":147,"lines":1081,"name":"honeypot-manager","sector":"Defense","status":"idle"},{"color":"#26c6da","description":"","display_name":"Log Forensics","exists":true,"id":148,"lines":445,"name":"log-forensics","sector":"Defense","status":"idle"},{"color":"#26c6da","description":"","display_name":"Incident Logger","exists":true,"id":149,"lines":772,"name":"incident-logger","sector":"Defense","status":"idle"},{"color":"#555555","description":"","display_name":"Ad Attacker","exists":true,"id":150,"lines":563,"name":"ad-attacker","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Ai Jailbreaker","exists":true,"id":151,"lines":648,"name":"ai-jailbreaker","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Android Tester","exists":true,"id":152,"lines":739,"name":"android-tester","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Ansible Runner","exists":true,"id":153,"lines":935,"name":"ansible-runner","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Antibot Reverser","exists":true,"id":154,"lines":783,"name":"antibot-reverser","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Api Automator","exists":true,"id":155,"lines":667,"name":"api-automator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Api Fuzzer","exists":true,"id":156,"lines":939,"name":"api-fuzzer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Api Gateway","exists":true,"id":157,"lines":202,"name":"api-gateway","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Api Parameter Bruter","exists":true,"id":158,"lines":371,"name":"api-parameter-bruter","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Architecture Advisor","exists":true,"id":159,"lines":861,"name":"architecture-advisor","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Attack Path Finder","exists":true,"id":160,"lines":532,"name":"attack-path-finder","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Audit Logger","exists":true,"id":161,"lines":602,"name":"audit-logger","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Auth Flow Breaker","exists":true,"id":162,"lines":451,"name":"auth-flow-breaker","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Auto Hardener","exists":true,"id":163,"lines":1228,"name":"auto-hardener","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Auto Healer","exists":true,"id":164,"lines":754,"name":"auto-healer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Auto Restarter","exists":true,"id":165,"lines":551,"name":"auto-restarter","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Auto Scaler","exists":true,"id":166,"lines":811,"name":"auto-scaler","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Backdoor Hunter","exists":true,"id":167,"lines":693,"name":"backdoor-hunter","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Bandwidth Monitor","exists":true,"id":168,"lines":343,"name":"bandwidth-monitor","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Batch Processor","exists":true,"id":169,"lines":712,"name":"batch-processor","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Bb Autopilot","exists":true,"id":170,"lines":1151,"name":"bb-autopilot","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Binary Analyzer","exists":true,"id":171,"lines":657,"name":"binary-analyzer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Bluetooth Tester","exists":true,"id":172,"lines":590,"name":"bluetooth-tester","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Boot Fixer","exists":true,"id":173,"lines":571,"name":"boot-fixer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Boot Repair","exists":true,"id":174,"lines":798,"name":"boot-repair","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Bounty Arbitrage","exists":true,"id":175,"lines":969,"name":"bounty-arbitrage","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Bounty Intel","exists":true,"id":176,"lines":334,"name":"bounty-intel","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Brute Forcer","exists":true,"id":177,"lines":991,"name":"brute-forcer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Bug Bounty Hunter","exists":true,"id":178,"lines":613,"name":"bug-bounty-hunter","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Bug Payout Predictor","exists":true,"id":179,"lines":771,"name":"bug-payout-predictor","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Capacity Planner","exists":true,"id":180,"lines":117,"name":"capacity-planner","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Change Manager","exists":true,"id":181,"lines":998,"name":"change-manager","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Chaos Tester","exists":true,"id":182,"lines":626,"name":"chaos-tester","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Cleanup Automator","exists":true,"id":183,"lines":742,"name":"cleanup-automator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Cloud Deployer","exists":true,"id":184,"lines":430,"name":"cloud-deployer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Cloudflare Slayer","exists":true,"id":185,"lines":199,"name":"cloudflare-slayer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Cluster Manager","exists":true,"id":186,"lines":404,"name":"cluster-manager","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Code Deployer","exists":true,"id":187,"lines":857,"name":"code-deployer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Code Reviewer","exists":true,"id":188,"lines":567,"name":"code-reviewer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Community Brain","exists":true,"id":189,"lines":871,"name":"community-brain","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Community Hub","exists":true,"id":190,"lines":1057,"name":"community-hub","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Config Fixer","exists":true,"id":191,"lines":649,"name":"config-fixer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Config Sync","exists":true,"id":192,"lines":766,"name":"config-sync","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Container Orchestrator","exists":true,"id":193,"lines":264,"name":"container-orchestrator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Context Flow Tracer","exists":true,"id":194,"lines":587,"name":"context-flow-tracer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Cors Chain","exists":true,"id":195,"lines":579,"name":"cors-chain","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Crash Analyzer","exists":true,"id":196,"lines":656,"name":"crash-analyzer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Credential Tester","exists":true,"id":197,"lines":791,"name":"credential-tester","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Cron Master","exists":true,"id":198,"lines":617,"name":"cron-master","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Crontab Auditor","exists":true,"id":199,"lines":78,"name":"crontab-auditor","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Crypto Analyzer","exists":true,"id":200,"lines":555,"name":"crypto-analyzer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Cryptojacker","exists":true,"id":201,"lines":579,"name":"cryptojacker","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Data Exfiltrator","exists":true,"id":202,"lines":610,"name":"data-exfiltrator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Database Repair","exists":true,"id":203,"lines":662,"name":"database-repair","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Debugger","exists":true,"id":204,"lines":748,"name":"debugger","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Decompiler","exists":true,"id":205,"lines":496,"name":"decompiler","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Dependency Manager","exists":true,"id":206,"lines":548,"name":"dependency-manager","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Dependency Resolver","exists":true,"id":207,"lines":662,"name":"dependency-resolver","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Deploy Automator","exists":true,"id":208,"lines":765,"name":"deploy-automator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Dev Environment","exists":true,"id":209,"lines":825,"name":"dev-environment","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Discord Bot Manager","exists":true,"id":210,"lines":655,"name":"discord-bot-manager","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Disk Doctor","exists":true,"id":211,"lines":573,"name":"disk-doctor","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Dns Poisoner","exists":true,"id":212,"lines":787,"name":"dns-poisoner","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Doc Generator","exists":true,"id":213,"lines":959,"name":"doc-generator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Docker Inspector","exists":true,"id":214,"lines":485,"name":"docker-inspector","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Dom Xss Scanner","exists":true,"id":215,"lines":266,"name":"dom-xss-scanner","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Drift Detector","exists":true,"id":216,"lines":650,"name":"drift-detector","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Dupe Checker","exists":true,"id":217,"lines":522,"name":"dupe-checker","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Electron Unpacker","exists":true,"id":218,"lines":416,"name":"electron-unpacker","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Email Automator","exists":true,"id":219,"lines":687,"name":"email-automator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Encoding Chain Builder","exists":true,"id":220,"lines":308,"name":"encoding-chain-builder","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Environment Manager","exists":true,"id":221,"lines":345,"name":"environment-manager","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Event Bus","exists":true,"id":222,"lines":1063,"name":"event-bus","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Event Reactor","exists":true,"id":223,"lines":602,"name":"event-reactor","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Exploit Researcher","exists":true,"id":224,"lines":830,"name":"exploit-researcher","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Exploit Validator","exists":true,"id":225,"lines":822,"name":"exploit-validator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Extension Analyzer","exists":true,"id":226,"lines":444,"name":"extension-analyzer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Failover Manager","exists":true,"id":227,"lines":773,"name":"failover-manager","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"File Manager","exists":true,"id":228,"lines":349,"name":"file-manager","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"File Watcher","exists":true,"id":229,"lines":532,"name":"file-watcher","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Finding Chain Builder","exists":true,"id":230,"lines":763,"name":"finding-chain-builder","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Firewall Architect","exists":true,"id":231,"lines":419,"name":"firewall-architect","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Firmware Extractor","exists":true,"id":232,"lines":641,"name":"firmware-extractor","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Forensics Analyst","exists":true,"id":233,"lines":1169,"name":"forensics-analyst","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Game Backup","exists":true,"id":234,"lines":534,"name":"game-backup","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Game Performance","exists":true,"id":235,"lines":572,"name":"game-performance","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Game Server Manager","exists":true,"id":236,"lines":630,"name":"game-server-manager","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Ghost Recon","exists":true,"id":237,"lines":637,"name":"ghost-recon","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Gtfobins Lookup","exists":true,"id":238,"lines":726,"name":"gtfobins-lookup","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Health Orchestrator","exists":true,"id":239,"lines":1034,"name":"health-orchestrator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Heartbeat Monitor","exists":true,"id":240,"lines":494,"name":"heartbeat-monitor","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Http2 Smuggler","exists":true,"id":241,"lines":506,"name":"http2-smuggler","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Hunt Authorization","exists":true,"id":242,"lines":67,"name":"hunt-authorization","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Hunter Base","exists":true,"id":243,"lines":929,"name":"hunter-base","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Identity Rotator","exists":true,"id":244,"lines":786,"name":"identity-rotator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Ios Tester","exists":true,"id":245,"lines":643,"name":"ios-tester","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Js Deobfuscator","exists":true,"id":246,"lines":520,"name":"js-deobfuscator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Kerberos Attacker","exists":true,"id":247,"lines":494,"name":"kerberos-attacker","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Keylogger Deployer","exists":true,"id":248,"lines":644,"name":"keylogger-deployer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Knowledge Forge","exists":true,"id":249,"lines":649,"name":"knowledge-forge","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Ldap Tester","exists":true,"id":250,"lines":535,"name":"ldap-tester","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Load Balancer","exists":true,"id":251,"lines":688,"name":"load-balancer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Log Aggregator","exists":true,"id":252,"lines":575,"name":"log-aggregator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Log Doctor","exists":true,"id":253,"lines":625,"name":"log-doctor","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Lolbas Finder","exists":true,"id":254,"lines":653,"name":"lolbas-finder","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Malware Analyst","exists":true,"id":255,"lines":617,"name":"malware-analyst","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Minecraft Server","exists":true,"id":256,"lines":703,"name":"minecraft-server","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Mod Manager","exists":true,"id":257,"lines":482,"name":"mod-manager","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Model Extractor","exists":true,"id":258,"lines":607,"name":"model-extractor","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Multi Agent Bounty Hunter","exists":true,"id":259,"lines":1395,"name":"multi-agent-bounty-hunter","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Multi Server","exists":true,"id":260,"lines":407,"name":"multi-server","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Multipart Fuzzer","exists":true,"id":261,"lines":316,"name":"multipart-fuzzer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Mxss Generator","exists":true,"id":262,"lines":244,"name":"mxss-generator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Nagasaki","exists":true,"id":263,"lines":335,"name":"nagasaki","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Network Fixer","exists":true,"id":264,"lines":604,"name":"network-fixer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Network Healer","exists":true,"id":265,"lines":635,"name":"network-healer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Network Sniffer","exists":true,"id":266,"lines":601,"name":"network-sniffer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Night Shift","exists":true,"id":267,"lines":248,"name":"night-shift","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Notification Router","exists":true,"id":268,"lines":726,"name":"notification-router","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Notifications","exists":true,"id":269,"lines":690,"name":"notifications","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Obfuscation Breaker","exists":true,"id":270,"lines":808,"name":"obfuscation-breaker","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Param Pollution Tester","exists":true,"id":271,"lines":358,"name":"param-pollution-tester","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Password Auditor","exists":true,"id":272,"lines":481,"name":"password-auditor","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Patch Validator","exists":true,"id":273,"lines":388,"name":"patch-validator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Pentest Scanner","exists":true,"id":274,"lines":775,"name":"pentest-scanner","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Permission Fixer","exists":true,"id":275,"lines":876,"name":"permission-fixer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Phishing Simulator","exists":true,"id":276,"lines":982,"name":"phishing-simulator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Player Manager","exists":true,"id":277,"lines":558,"name":"player-manager","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Privilege Escalator","exists":true,"id":278,"lines":947,"name":"privilege-escalator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Process Forensics","exists":true,"id":279,"lines":91,"name":"process-forensics","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Program Monitor","exists":true,"id":280,"lines":492,"name":"program-monitor","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Project Planner","exists":true,"id":281,"lines":922,"name":"project-planner","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Prompt Injection Tester","exists":true,"id":282,"lines":1185,"name":"prompt-injection-tester","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Protocol Reverser","exists":true,"id":283,"lines":640,"name":"protocol-reverser","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Proxy Core","exists":true,"id":284,"lines":803,"name":"proxy-core","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Proxy Manager","exists":true,"id":285,"lines":453,"name":"proxy-manager","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Purple Team Autopilot","exists":true,"id":286,"lines":1081,"name":"purple-team-autopilot","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Ransomware Tester","exists":true,"id":287,"lines":633,"name":"ransomware-tester","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Rate Limit Tester","exists":true,"id":288,"lines":283,"name":"rate-limit-tester","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Red Team","exists":true,"id":289,"lines":787,"name":"red-team","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Redirect Chain Tracer","exists":true,"id":290,"lines":382,"name":"redirect-chain-tracer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Redundancy Manager","exists":true,"id":291,"lines":655,"name":"redundancy-manager","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Refactorer","exists":true,"id":292,"lines":520,"name":"refactorer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Repo Manager","exists":true,"id":293,"lines":776,"name":"repo-manager","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Report Generator","exists":true,"id":294,"lines":817,"name":"report-generator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Report Writer","exists":true,"id":295,"lines":747,"name":"report-writer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Resource Estimator","exists":true,"id":296,"lines":925,"name":"resource-estimator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Retry Engine","exists":true,"id":297,"lines":746,"name":"retry-engine","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Reverse Engineer","exists":true,"id":298,"lines":814,"name":"reverse-engineer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Rootkit Builder","exists":true,"id":299,"lines":771,"name":"rootkit-builder","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Runbook Executor","exists":true,"id":300,"lines":1085,"name":"runbook-executor","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Scheduler","exists":true,"id":301,"lines":785,"name":"scheduler","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Scope Parser","exists":true,"id":302,"lines":629,"name":"scope-parser","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Script Builder","exists":true,"id":303,"lines":923,"name":"script-builder","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Secret Rotator","exists":true,"id":304,"lines":826,"name":"secret-rotator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Self Improver","exists":true,"id":305,"lines":505,"name":"self-improver","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Service Healer","exists":true,"id":306,"lines":783,"name":"service-healer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Session Hijacker","exists":true,"id":307,"lines":938,"name":"session-hijacker","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Smart Contract Auditor","exists":true,"id":308,"lines":497,"name":"smart-contract-auditor","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Smb Tester","exists":true,"id":309,"lines":438,"name":"smb-tester","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Snapshot Manager","exists":true,"id":310,"lines":720,"name":"snapshot-manager","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Social Engineer","exists":true,"id":311,"lines":626,"name":"social-engineer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Spray Scanner","exists":true,"id":312,"lines":577,"name":"spray-scanner","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Ssl Watchdog","exists":true,"id":313,"lines":750,"name":"ssl-watchdog","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Sso Analyzer","exists":true,"id":314,"lines":266,"name":"sso-analyzer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Stealth Core","exists":true,"id":315,"lines":802,"name":"stealth-core","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Steam Server","exists":true,"id":316,"lines":627,"name":"steam-server","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Subdomain Takeover","exists":true,"id":317,"lines":592,"name":"subdomain-takeover","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Supply Chain Attacker","exists":true,"id":318,"lines":733,"name":"supply-chain-attacker","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"System Profiler","exists":true,"id":319,"lines":385,"name":"system-profiler","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Target Pipeline","exists":true,"id":320,"lines":146,"name":"target-pipeline","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Target Researcher","exists":true,"id":321,"lines":463,"name":"target-researcher","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Target Vault","exists":true,"id":322,"lines":1140,"name":"target-vault","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Task Automator","exists":true,"id":323,"lines":582,"name":"task-automator","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Task Queue","exists":true,"id":324,"lines":837,"name":"task-queue","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Telegram Bot","exists":true,"id":325,"lines":347,"name":"telegram-bot","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Test Runner","exists":true,"id":326,"lines":1212,"name":"test-runner","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Time Watcher","exists":true,"id":327,"lines":822,"name":"time-watcher","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Trace Cleaner","exists":true,"id":328,"lines":645,"name":"trace-cleaner","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Traffic Analyzer","exists":true,"id":329,"lines":906,"name":"traffic-analyzer","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Trigger Builder","exists":true,"id":330,"lines":739,"name":"trigger-builder","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Tunnel Builder","exists":true,"id":331,"lines":690,"name":"tunnel-builder","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Update Manager","exists":true,"id":332,"lines":391,"name":"update-manager","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Uptime Guardian","exists":true,"id":333,"lines":678,"name":"uptime-guardian","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Vpn Manager","exists":true,"id":334,"lines":417,"name":"vpn-manager","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Vuln Predictor","exists":true,"id":335,"lines":726,"name":"vuln-predictor","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Vuln Tracker","exists":true,"id":336,"lines":581,"name":"vuln-tracker","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Waf Combo Splitter","exists":true,"id":337,"lines":294,"name":"waf-combo-splitter","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Waf Source Auditor","exists":true,"id":338,"lines":670,"name":"waf-source-auditor","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Wasm Reverser","exists":true,"id":339,"lines":431,"name":"wasm-reverser","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Web App Scanner","exists":true,"id":340,"lines":476,"name":"web-app-scanner","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Web Proxy Agent","exists":true,"id":341,"lines":2749,"name":"web-proxy-agent","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Webhook Listener","exists":true,"id":342,"lines":593,"name":"webhook-listener","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Webhook Manager","exists":true,"id":343,"lines":784,"name":"webhook-manager","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Whmcs Doctor","exists":true,"id":344,"lines":605,"name":"whmcs-doctor","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Wifi Breaker","exists":true,"id":345,"lines":598,"name":"wifi-breaker","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Workflow Engine","exists":true,"id":346,"lines":920,"name":"workflow-engine","sector":"Other","status":"idle"},{"color":"#555555","description":"","display_name":"Zero Day Hunter","exists":true,"id":347,"lines":1131,"name":"zero-day-hunter","sector":"Other","status":"idle"}];
        this.agents = data;
        document.getElementById('stat-wolves').textContent = this.agents.length;
        this.buildSectors();
        this.layoutBuildings();
        this.renderSectorPanel();
        this.animate();
        this.log('SYSTEM', `${this.agents.length} wolves loaded across ${this.sectorOrder.length} sectors.`);
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
        }).catch(() => {
            this.log('SYSTEM', 'Hunt requires Wolf Alpha server. Run: python3 wolf-den/app.py', 'alert');
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
            fetch('/api/agent/' + agent.name).catch(() => null).then(r => r ? r.json() : null).then(data => {
                if (!data) { document.getElementById('intel-code').textContent = '[ Connect to Wolf Alpha server for full playbook ]'; return; }
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
