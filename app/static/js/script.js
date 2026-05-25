const UI_TEXT = {
  emptySummary: 'Selecciona una subherramienta y pulsa Ejecutar.',
  emptyParallel: 'Selecciona herramientas arriba y pulsa Lanzar.',
  emptyStructured: 'No se encontraron datos estructurados. Revisa el output completo.',
  missingCommand: 'Selecciona una subherramienta o escribe un comando.',
  missingTarget: 'Introduce un objetivo real arriba antes de ejecutar.',
  running: 'Ejecutando...',
  runningFromPlan: 'Ejecutando desde plan...'
};

// ── Elapsed timer per tool ────────────────────────────────────────────────────
const _runTimers = {};

function startTimer(tool) {
  stopTimer(tool);
  _runTimers[tool + '_start'] = Date.now();
  _runTimers[tool] = setInterval(() => {
    const srEl = $(`sr-${tool}`);
    if (!srEl || srEl.style.display === 'none') return;
    const timeEl = srEl.querySelector('.elapsed-time');
    if (timeEl) timeEl.textContent = _fmtSecs(Math.floor((Date.now() - _runTimers[tool + '_start']) / 1000));
  }, 500);
}

function stopTimer(tool) {
  if (_runTimers[tool]) {
    clearInterval(_runTimers[tool]);
    delete _runTimers[tool];
  }
}

function getElapsed(tool) {
  const start = _runTimers[tool + '_start'];
  return start ? _fmtSecs(Math.floor((Date.now() - start) / 1000)) : '';
}

function _fmtSecs(s) {
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}

setInterval(() => {
  const clock = document.getElementById('clock');
  if (clock) {
    clock.textContent = new Date().toLocaleTimeString('es-ES');
  }
}, 1000);

let target = '';
const runningRequests = {};
const selectedSubtool = {};
const _structuredCache = {}; // stores structured JSON until 'done' arrives

const TOOL_COLORS = {
  discover:   { bg: '#fff7ed', color: '#c2410c', border: '#fed7aa' },
  amass:      { bg: '#eff6ff', color: '#1d4ed8', border: '#bfdbfe' },
  katana:     { bg: '#f5f3ff', color: '#6d28d9', border: '#ddd6fe' },
  wayback:    { bg: '#f0fdf4', color: '#15803d', border: '#bbf7d0' },
  identidad:  { bg: '#fdf4ff', color: '#7e22ce', border: '#e9d5ff' },
  subfinder:  { bg: '#f0fdfa', color: '#0f766e', border: '#99f6e4' },
  webrecon:   { bg: '#fff1f2', color: '#be123c', border: '#fecdd3' },
  shodancli:  { bg: '#f0f9ff', color: '#0369a1', border: '#bae6fd' },
  nuclei:     { bg: '#fff7ed', color: '#c2410c', border: '#fed7aa' },
  urls:       { bg: '#f7fee7', color: '#3f6212', border: '#d9f99d' },
};

// Extracts apex domain from a subdomain. IPs/CIDRs returned as-is.
function _apexDomain(t) {
  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d+)?$/.test(t)) return t;
  const parts = t.split('.');
  if (parts.length <= 2) return t;
  const twoPartTLDs = ['co.uk','com.au','co.nz','co.jp','com.br','com.mx','com.ar','co.es','org.uk','net.au'];
  if (twoPartTLDs.includes(parts.slice(-2).join('.'))) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

const SUBTOOLS = {
  discover: [
    { name: 'theHarvester', func: 'Emails, subdominios, IPs desde APIs OSINT', alert: 'none', apexOnly: true, cmd: t => `script -q -c "theHarvester -d ${t} -b baidu,certspotter,crtsh,duckduckgo,hackertarget,urlscan" /dev/null` },
    { name: 'DNSRecon', func: 'Registros DNS: A, AAAA, MX, NS, TXT, SOA', alert: 'low', apexOnly: true, cmd: t => `dnsrecon -d ${t}` },
    { name: 'WHOIS', func: 'Propietario, fechas y nameservers', alert: 'none', apexOnly: true, cmd: t => `whois ${t}` },
    { name: 'WafW00f', func: 'Detecta y fingerprinta WAFs', alert: 'med', cmd: t => `wafw00f https://${t}` },
    { name: 'WhatWeb', func: 'CMS, frameworks y versiones del servidor', alert: 'low', cmd: t => `timeout 45 whatweb --no-errors --open-timeout=10 --read-timeout=20 ${t}` },
    { name: 'Traceroute', func: 'Ruta de red hasta el objetivo', alert: 'low', cmd: t => `traceroute ${t}` },
    { name: 'Nmap top1000', func: 'SYN scan de los 1000 puertos más comunes', alert: 'high', cmd: t => `nmap -sS -T3 ${t}` },
    { name: 'Nmap + versiones', func: 'Detección de servicios y versiones', alert: 'high', cmd: t => `nmap -sV -T3 ${t}` },
    { name: 'Nmap + NSE', func: 'Scripts NSE automáticos de reconocimiento', alert: 'high', cmd: t => `nmap -sC -sV -T3 ${t}` },
    { name: 'enum4linux', func: 'Usuarios, shares y políticas SMB', alert: 'high', cmd: t => `enum4linux ${t}` },
    { name: 'smbclient', func: 'Recursos compartidos SMB', alert: 'med', cmd: t => `smbclient -L ${t} -N` },
    { name: 'ike-scan', func: 'Gateways VPN IPsec', alert: 'med', cmd: t => `ike-scan ${t}` },
    { name: 'Nikto', func: '5000+ peticiones buscando configs inseguros', alert: 'high', cmd: t => `nikto -h ${t}` },
    { name: 'sslscan', func: 'Versiones TLS, cipher suites y certificados', alert: 'med', cmd: t => `sslscan ${t}` },
    { name: 'sslyze', func: 'Análisis profundo TLS: ROBOT, Heartbleed', alert: 'med', cmd: t => `sslyze ${t}` },
    { name: 'httpx — probe', func: 'Estado HTTP, título, servidor y tecnologías detectadas', alert: 'low', cmd: t => `/home/kali/Aletheia-Dashboard/httpx-probe.sh https://${t} -sc -title -web-server -tech-detect -ip -silent -nc` },
    { name: 'dnsx — registros', func: 'Consulta A, AAAA, MX, NS, TXT, CNAME con respuesta', alert: 'none', apexOnly: true, cmd: t => `/home/kali/Aletheia-Dashboard/dnsx-probe.sh ${t} -a -aaaa -mx -ns -txt -cname -resp -silent` },
  ],
  amass: [
    { name: 'intel', func: 'Dominios por WHOIS inverso y ASNs', alert: 'none', apexOnly: true, cmd: t => `amass intel -whois -d ${t}` },
    { name: 'enum -passive', func: 'Subdominios solo con fuentes OSINT', alert: 'none', apexOnly: true, cmd: t => `amass enum -passive -d ${t}` },
    { name: 'enum -active', func: 'Valida subdominios con DNS activo', alert: 'low', apexOnly: true, cmd: t => `amass enum -active -d ${t}` },
    { name: 'enum -brute', func: 'Fuerza bruta DNS con resolvers públicos', alert: 'med', apexOnly: true, cmd: t => `amass enum -brute -r 8.8.8.8,1.1.1.1 -d ${t}` }
  ],
  katana: [
    { name: 'Estático', func: 'Rastrea HTML sin JS', alert: 'low', cmd: t => `katana -u https://${t} -rl 20 -silent` },
    { name: 'Con JS (-jc)', func: 'Analiza .js buscando endpoints', alert: 'low', cmd: t => `katana -u https://${t} -jc -rl 20 -silent` },
    { name: 'Headless', func: 'Chrome real para ejecutar JS', alert: 'med', cmd: t => `katana -u https://${t} -headless -rl 15 -c 5 -no-sandbox` },
    { name: 'robots + sitemap', func: 'Lee robots.txt y sitemap.xml', alert: 'low', cmd: t => `katana -u https://${t} -kf robotstxt,sitemapxml -rl 20 -silent` },
    { name: 'Deep crawl', func: 'Crawling profundo depth 5', alert: 'med', cmd: t => `katana -u https://${t} -jc -kf robotstxt,sitemapxml -rl 10 -depth 5 -silent` },
    { name: 'Con sesión', func: 'Crawling autenticado con cookie', alert: 'med', cmd: t => `katana -u https://${t} -H "Cookie: session=PEGAR_AQUI" -headless -rl 10` }
  ],
  wayback: [
    { name: 'Listar snapshots', func: 'Muestra todas las versiones archivadas del sitio (sin descargar)', alert: 'none', cmd: t => `wayback_machine_downloader https://${t} -d /home/kali/aletheia-downloads/websites/${t} -p 1` },
    { name: 'Snapshots desde 2020', func: 'Versiones archivadas a partir de enero 2020', alert: 'none', cmd: t => `wayback_machine_downloader https://${t} -d /home/kali/aletheia-downloads/websites/${t} -f 20200101000000 -p 1` },
    { name: 'Descargar sitio completo', func: 'Descarga la última versión archivada del sitio', alert: 'low', cmd: t => `wayback_machine_downloader https://${t} -d /home/kali/aletheia-downloads/websites/${t} -c 5` }
  ],
  identidad: [
    { name: 'Sherlock', func: 'Busca el alias en +300 redes sociales', alert: 'none', cmd: t => `sherlock ${t} --print-found --local --no-txt` },
    { name: 'Sherlock (timeout 15s)', func: 'Búsqueda rápida con tiempo límite por sitio', alert: 'none', cmd: t => `sherlock ${t} --print-found --local --no-txt --timeout 15` },
    { name: 'Maigret', func: 'Búsqueda profunda en +3000 sitios', alert: 'none', cmd: t => `maigret ${t}` },
    { name: 'Maigret (reporte HTML)', func: 'Genera informe HTML con el perfil completo', alert: 'none', cmd: t => `maigret ${t} --html /tmp/aletheia/maigret_${t.replace(/[\/:.]/g, '_')}.html` },
    { name: 'Holehe (email)', func: 'Solo emails — qué servicios tienen esa cuenta asociada', alert: 'none', inputType: 'email', cmd: t => `holehe ${t}` },
    { name: 'Blackbird (username)', func: 'Busca el alias en +500 sitios, devuelve JSON', alert: 'none', cmd: t => `blackbird -u ${t}` },
    { name: 'Blackbird (email)', func: 'Solo emails — busca cuentas asociadas en +500 sitios', alert: 'none', inputType: 'email', cmd: t => `blackbird -e ${t}` },
    { name: 'usufy (OSRFramework)', func: 'Verifica el alias en cientos de plataformas con OSRFramework', alert: 'none', cmd: t => `usufy -n ${t}` },
    { name: 'searchfy (OSRFramework)', func: 'Busca el término en buscadores y redes sociales', alert: 'none', cmd: t => `searchfy -q "${t}"` }
  ],
  subfinder: [
    { name: 'Pasivo básico', func: 'Descubrimiento de subdominios solo con fuentes OSINT', alert: 'none', inputType: 'domain', apexOnly: true, cmd: t => `subfinder -d ${t} -silent` },
    { name: 'Todas las fuentes', func: 'Usa todas las fuentes disponibles incluyendo APIs', alert: 'none', inputType: 'domain', apexOnly: true, cmd: t => `subfinder -d ${t} -all -silent` },
    { name: 'Recursivo', func: 'Enumera subdominios de subdominios (más profundo)', alert: 'low', inputType: 'domain', apexOnly: true, cmd: t => `subfinder -d ${t} -recursive -silent` },
    { name: 'Con timeout extendido', func: 'Búsqueda con 60s de timeout por fuente', alert: 'low', inputType: 'domain', apexOnly: true, cmd: t => `subfinder -d ${t} -all -silent -timeout 60` },
    { name: 'Exportar a fichero', func: 'Guarda resultados en /tmp/aletheia/subfinder_dominio.txt', alert: 'none', inputType: 'domain', apexOnly: true, cmd: t => `subfinder -d ${t} -all -silent -o /tmp/aletheia/subfinder_${t}.txt` }
  ],
  webrecon: [
    { name: 'Photon — rastreo básico', func: 'Extrae URLs, emails y archivos de un sitio web', alert: 'low', inputType: 'domain', cmd: t => `photon -u https://${t} -t 5 -o /tmp/aletheia/photon_${t.replace(/[\/:.]/g,'_')}` },
    { name: 'Photon — profundo', func: 'Rastreo profundo (nivel 3) extrayendo claves y secretos', alert: 'med', inputType: 'domain', cmd: t => `photon -u https://${t} -l 3 -t 10 -o /tmp/aletheia/photon_${t.replace(/[\/:.]/g,'_')} --keys` },
    { name: 'Photon — solo URLs internas', func: 'Extrae únicamente rutas internas del dominio objetivo', alert: 'low', inputType: 'domain', cmd: t => `photon -u https://${t} -t 5 --only-urls -o /tmp/aletheia/photon_${t.replace(/[\/:.]/g,'_')}` },
    { name: 'FinalRecon — completo', func: 'Cabeceras, SSL, WHOIS, DNS y subdominios en un solo paso', alert: 'low', inputType: 'domain', cmd: t => `finalrecon --url https://${t} --full` },
    { name: 'FinalRecon — cabeceras + SSL', func: 'Analiza cabeceras HTTP y certificado TLS', alert: 'none', inputType: 'domain', cmd: t => `finalrecon --url https://${t} --headers --sslinfo` },
    { name: 'FinalRecon — DNS + subdominios', func: 'Registros DNS y enumeración pasiva de subdominios', alert: 'none', inputType: 'domain', cmd: t => `finalrecon --url https://${t} --dns --sub` }
  ],
  shodancli: [
    { name: 'Host info', func: 'Puertos, servicios y vulnerabilidades conocidas de una IP', alert: 'none', inputType: 'ip', cmd: t => `shodan host ${t}` },
    { name: 'Domain info', func: 'IPs, subdominios y historial asociados al dominio', alert: 'none', inputType: 'domain', apexOnly: true, cmd: t => `shodan domain ${t}` },
    { name: 'Search hostname', func: 'Busca todos los activos del dominio en el índice de Shodan', alert: 'none', inputType: 'domain', apexOnly: true, cmd: t => `shodan search --fields ip_str,port,org,hostnames "hostname:${t}"` },
    { name: 'Search org', func: 'Activos públicos de la organización en Shodan', alert: 'none', cmd: t => `shodan search --fields ip_str,port,org "org:${t}"` },
    { name: 'Count activos', func: 'Número total de activos indexados sin gastar créditos', alert: 'none', inputType: 'domain', apexOnly: true, cmd: t => `shodan count "hostname:${t}"` }
  ],
  nuclei: [
    { name: 'Severidad media+', func: 'Detecta vulns medium, high y critical con templates por defecto', alert: 'high', cmd: t => `nuclei -u https://${t} -severity medium,high,critical -silent` },
    { name: 'CVEs conocidos', func: 'Solo templates de CVEs catalogados', alert: 'high', cmd: t => `nuclei -u https://${t} -tags cve -severity medium,high,critical -silent` },
    { name: 'Misconfigs + exposures', func: 'Configuraciones inseguras y archivos expuestos', alert: 'med', cmd: t => `nuclei -u https://${t} -tags misconfigs,exposures -silent` },
    { name: 'Tech detect', func: 'Fingerprinting de tecnologías y versiones', alert: 'none', cmd: t => `nuclei -u https://${t} -tags tech -silent` },
    { name: 'Escaneo completo', func: 'Todos los templates: info, low, medium, high, critical', alert: 'high', cmd: t => `nuclei -u https://${t} -severity info,low,medium,high,critical -silent` },
  ],
  urls: [
    { name: 'gau — todas las fuentes', func: 'URLs históricas desde Wayback, CommonCrawl, OTX y URLScan', alert: 'none', inputType: 'domain', apexOnly: true, cmd: t => `gau ${t} --threads 5 --subs` },
    { name: 'gau — Wayback + OTX', func: 'Solo fuentes Wayback Machine y AlienVault OTX', alert: 'none', inputType: 'domain', apexOnly: true, cmd: t => `gau ${t} --threads 5 --providers wayback,otx` },
    { name: 'gau — desde 2020', func: 'URLs archivadas a partir de enero 2020', alert: 'none', inputType: 'domain', apexOnly: true, cmd: t => `gau ${t} --threads 5 --from 202001` },
    { name: 'waybackurls', func: 'URLs desde Wayback Machine (tomnomnom)', alert: 'none', inputType: 'domain', apexOnly: true, cmd: t => `/home/kali/Aletheia-Dashboard/waybackurls-probe.sh ${t}` },
  ],
};

const toolList = ['discover', 'amass', 'katana', 'wayback', 'identidad', 'subfinder', 'webrecon', 'shodancli', 'nuclei', 'urls'];

const toolMeta = {
  discover: {
    title: '🔍 Discover',
    desc: 'Framework orquestador para reconocimiento inicial.',
    tags: '<span class="tag tag-mit">MIT</span><span class="tag tag-npsl">Nmap NPSL</span>'
  },
  amass: {
    title: '🌐 Amass',
    desc: 'Enumeración de subdominios con múltiples fuentes.',
    tags: '<span class="tag tag-apache">Apache 2.0</span>'
  },
  katana: {
    title: '🕷 Katana',
    desc: 'Crawling web estático, JS y headless.',
    tags: '<span class="tag tag-mit">MIT</span>'
  },
  wayback: {
    title: '📼 Wayback Machine',
    desc: 'Accede a versiones archivadas de sitios web a través de Internet Archive.',
    tags: '<span class="tag tag-mit">MIT</span>'
  },
  identidad: {
    title: '👤 Identidad',
    desc: 'Huella digital de personas: búsqueda de alias y emails en redes sociales y servicios.',
    tags: '<span class="tag tag-mit">MIT</span>'
  },
  subfinder: {
    title: '🔎 Subfinder',
    desc: 'Descubrimiento rápido de subdominios con múltiples fuentes OSINT pasivas.',
    tags: '<span class="tag tag-mit">MIT</span>'
  },
  webrecon: {
    title: '🕸 Web Recon',
    desc: 'Crawling y reconocimiento web: extracción de URLs, emails, claves y análisis de cabeceras.',
    tags: '<span class="tag tag-mit">MIT</span>'
  },
  shodancli: {
    title: '📡 Shodan CLI',
    desc: 'Consultas directas a Shodan desde terminal: hosts, dominios, búsquedas y conteos.',
    tags: '<span class="tag tag-mit">MIT</span>'
  },
  nuclei: {
    title: '☢ Nuclei',
    desc: 'Scanner de vulnerabilidades basado en templates: CVEs, misconfigs, exposures y tech-detect.',
    tags: '<span class="tag tag-mit">MIT</span>'
  },
  urls: {
    title: '🔗 URL Discovery',
    desc: 'Recopila URLs históricas y archivadas desde Wayback Machine, CommonCrawl, OTX y URLScan.',
    tags: '<span class="tag tag-mit">MIT</span>'
  },
};

function $(id) {
  return document.getElementById(id);
}

function escHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function makeInfoText(text, type = 'muted') {
  const cls = type === 'error' ? 'ui-message ui-message-error' : 'ui-message';
  return `<p class="${cls}">${escHtml(text)}</p>`;
}

function setHtml(id, html) {
  const el = $(id);
  if (el) el.innerHTML = html;
}

function setText(id, text) {
  const el = $(id);
  if (el) el.textContent = text;
}

function updateTarget(value) {
  target = value.trim();

  const chip = $('targetChip');
  if (chip) {
    chip.textContent = `🎯 ${target}`;
    chip.style.display = target ? 'inline-flex' : 'none';
  }

  // Update home panel target display
  const htv = $('homeTargetValue');
  if (htv) htv.textContent = target || 'Sin objetivo definido';
  const hts = $('homeTargetStatus');
  if (hts) hts.textContent = target ? 'ACTIVO' : 'READY';

  Object.keys(selectedSubtool).forEach(tool => {
    const idx = selectedSubtool[tool];
    if (idx !== undefined) buildPreview(tool, idx);
  });

  _updateScopeIndicator();
}

function show(id, btn) {
  const currentPanel = document.querySelector('.panel.active');
  const nextPanel = document.getElementById(`panel-${id}`);

  if (!nextPanel || currentPanel === nextPanel) {
    document.querySelectorAll('.nav-btn').forEach(button => button.classList.remove('active'));
    if (btn) {
      btn.classList.add('active');
    } else {
      const matching = [...document.querySelectorAll('.nav-btn')].find(button =>
        button.textContent.trim().toLowerCase().includes(id.toLowerCase())
      );
      if (matching) matching.classList.add('active');
    }
    return;
  }

  document.querySelectorAll('.nav-btn').forEach(button => button.classList.remove('active'));
  if (btn) {
    btn.classList.add('active');
  } else {
    const matching = [...document.querySelectorAll('.nav-btn')].find(button =>
      button.textContent.trim().toLowerCase().includes(id.toLowerCase())
    );
    if (matching) matching.classList.add('active');
  }

  if (currentPanel) {
    currentPanel.classList.remove('active');
  }

  nextPanel.classList.add('active');
  nextPanel.scrollTop = 0;

  const content = document.querySelector('.content');
  if (content) content.scrollTop = 0;

  if (id === 'pipeline') {
    const seedsEl = document.getElementById('pl-seeds');
    if (seedsEl && !seedsEl.value.trim()) {
      const scope = getScope();
      if (scope) {
        const targets = [...(scope.domains || []), ...(scope.ipRanges || [])];
        if (targets.length) seedsEl.value = targets.join('\n');
      }
    }
    if (typeof loadHistory === 'function') loadHistory();
  }
  if (id === 'parallel') {
    if (typeof loadManualHistory === 'function') loadManualHistory();
  }
}

function alertBadge(level) {
  const map = {
    none: ['al-none', 'Sin alerta'],
    low: ['al-low', 'Baja'],
    med: ['al-med', 'Media'],
    high: ['al-high', 'Alta']
  };

  const [cls, label] = map[level] || ['al-none', '—'];
  return `<span class="alert-badge ${cls}">${label}</span>`;
}

function buildToolPanels() {
  const container = $('tool-panels');
  if (!container) return;

  toolList.forEach(tool => {
    const meta = toolMeta[tool];
    const panelHtml = `
      <div class="panel" id="panel-${tool}">
        <div class="page-header">
          <div class="page-title">${meta.title} ${meta.tags}</div>
          <div class="page-desc">${meta.desc}</div>
        </div>

        <div class="subtool-grid" id="sg-${tool}"></div>

        <div class="terminal-box" id="tb-${tool}" style="display:none">
          <div class="terminal-label">Terminal — edita o revisa el comando</div>
          <div class="terminal-row">
            <span class="terminal-prompt">root@kali:~#</span>
            <input class="terminal-input" id="cmd-${tool}" placeholder="Escribe o edita el comando..." spellcheck="false">
          </div>
        </div>

        <div class="actions-row">
          <button class="run-btn" id="run-${tool}" onclick="runTool('${tool}')">▶ Ejecutar</button>
          <button class="stop-btn" id="stop-${tool}" onclick="stopTool('${tool}')">⬛ Parar</button>
        </div>

        <div class="output-section">
          <div class="output-header">
            <span class="output-title">Resultados</span>
            <span class="hist-badge" id="hist-badge-${tool}" style="display:none">♻ restaurado</span>
            <button class="dl-btn" id="dl-btn-${tool}" onclick="downloadOut('${tool}')" style="display:none">⬇ Exportar</button>
            <button class="clr-btn" onclick="clearOut('${tool}')">Limpiar</button>
          </div>

          <div class="out-tabs">
            <button class="out-tab active" onclick="switchTab('${tool}','parsed',this)">Resumen</button>
            <button class="out-tab" onclick="switchTab('${tool}','raw',this)">Output completo <span class="line-count-badge"></span></button>
          </div>

          <div class="out-tab-content active" id="parsed-${tool}">
            <div class="results-area" id="results-${tool}">
              ${makeInfoText(UI_TEXT.emptySummary)}
            </div>
          </div>

          <div class="out-tab-content" id="raw-${tool}">
            <div class="raw-output" id="raw-out-${tool}"></div>
          </div>

          <div class="status-bar">
            <div class="status-running" id="sr-${tool}">
              <div class="spinner"></div>
              Ejecutando…&nbsp;<span class="elapsed-time">0s</span>
            </div>
            <div class="status-done" id="sd-${tool}">✓ Completado <span class="elapsed-done" id="et-${tool}"></span></div>
            <span id="ss-${tool}">Listo</span>
          </div>
        </div>
      </div>
    `;

    container.insertAdjacentHTML('beforeend', panelHtml);

    const grid = $(`sg-${tool}`);
    SUBTOOLS[tool].forEach((subtool, idx) => {
      const card = document.createElement('div');
      card.className = 'subtool-card';
      card.id = `card-${tool}-${idx}`;
      card.innerHTML = `
        <div class="sc-top">
          <span class="sc-name">${subtool.name}</span>
          ${alertBadge(subtool.alert)}
        </div>
        <div class="sc-func">${subtool.func}</div>
      `;
      card.onclick = () => selectSubtool(tool, idx, card);
      grid.appendChild(card);
    });

    restoreHistory(tool);
  });
}

function buildParallelGrid() {
  const parallelGrid = $('parallel-subtool-grid');
  if (!parallelGrid || parallelGrid.hasChildNodes()) return;

  toolList.forEach(tool => {
    const color = TOOL_COLORS[tool];

    // Section header
    const header = document.createElement('div');
    header.className = 'pg-section-header';
    header.innerHTML = `
      <span class="pg-tool-badge" style="background:${color.bg};color:${color.color};border:1px solid ${color.border}">
        ${tool.toUpperCase()}
      </span>
      <span class="pg-tool-name">${toolMeta[tool].title}</span>
      <button class="pg-select-all" data-tool="${tool}" onclick="toggleSelectAll('${tool}')">Seleccionar todo</button>
    `;
    parallelGrid.appendChild(header);

    // Cards grid
    const grid = document.createElement('div');
    grid.className = 'pg-cards-grid';
    grid.id = `psg-${tool}`;
    parallelGrid.appendChild(grid);

    SUBTOOLS[tool].forEach((subtool, idx) => {
      const card = document.createElement('div');
      card.className = 'pg-card';
      card.dataset.tool = tool;
      card.dataset.idx = idx;

      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.className = 'pg-checkbox';
      checkbox.dataset.tool = tool;
      checkbox.dataset.idx = idx;
      checkbox.onchange = updateParallelCount;

      card.innerHTML = `
        <div class="pg-card-top">
          <span class="pg-card-name">${subtool.name}</span>
          ${alertBadge(subtool.alert)}
        </div>
        <div class="pg-card-desc">${subtool.func}</div>
      `;
      card.insertBefore(checkbox, card.firstChild);

      card.onclick = (e) => {
        if (e.target !== checkbox) {
          checkbox.checked = !checkbox.checked;
          updateParallelCount();
        }
        card.classList.toggle('pg-selected', checkbox.checked);
      };
      checkbox.onchange = () => {
        card.classList.toggle('pg-selected', checkbox.checked);
        updateParallelCount();
      };

      grid.appendChild(card);
    });
  });
}

function toggleSelectAll(tool) {
  const checkboxes = document.querySelectorAll(`#psg-${tool} .pg-checkbox`);
  const allChecked = [...checkboxes].every(cb => cb.checked);
  checkboxes.forEach(cb => {
    cb.checked = !allChecked;
    const card = cb.closest('.pg-card');
    if (card) card.classList.toggle('pg-selected', cb.checked);
  });
  // update button label
  const btn = document.querySelector(`.pg-select-all[data-tool="${tool}"]`);
  if (btn) btn.textContent = allChecked ? 'Seleccionar todo' : 'Deseleccionar todo';
  updateParallelCount();
}

function updateParallelCount() {
  const checked = document.querySelectorAll('#parallel-subtool-grid .pg-checkbox:checked').length;
  setText('parallel-count', `${checked} seleccionada${checked === 1 ? '' : 's'}`);
  const launchBtn = $('launch-parallel-btn');
  if (launchBtn) launchBtn.disabled = checked === 0;
}

function selectSubtool(tool, idx, card) {
  document.querySelectorAll(`#sg-${tool} .subtool-card`).forEach(item => item.classList.remove('selected'));
  card.classList.add('selected');
  selectedSubtool[tool] = idx;
  buildPreview(tool, idx);
}

function buildPreview(tool, idx) {
  const subtool = SUBTOOLS[tool][idx];
  const fullCmd = subtool.cmd(target || 'OBJETIVO');
  const input = $(`cmd-${tool}`);
  const box = $(`tb-${tool}`);

  if (input) input.value = fullCmd;
  if (box) box.style.display = 'block';
}

function switchTab(tool, tab, btn) {
  const section = btn.closest('.output-section');
  section.querySelectorAll('.out-tab').forEach(item => item.classList.remove('active'));
  section.querySelectorAll('.out-tab-content').forEach(item => item.classList.remove('active'));

  btn.classList.add('active');
  $(`${tab}-${tool}`).classList.add('active');
}

function collectWhatWebData(lines) {
  const data = {
    urls: [],
    ips: [],
    titles: [],
    servers: [],
    technologies: []
  };

  const urlSet = new Set();
  const ipSet = new Set();
  const titleSet = new Set();
  const serverSet = new Set();
  const techSet = new Set();

  lines.forEach(line => {
    const clean = line.trim();
    if (!clean) return;

    const urlMatch = clean.match(/^https?:\/\/[^\s\[]+/i);
    if (urlMatch) urlSet.add(urlMatch[0]);

    const ipMatch = clean.match(/IP\[([^\]]+)\]/i);
    if (ipMatch) ipSet.add(ipMatch[1].trim());

    const titleMatch = clean.match(/Title\[([^\]]+)\]/i);
    if (titleMatch) titleSet.add(titleMatch[1].trim());

    const serverMatch = clean.match(/HTTPServer\[([^\]]+)\]/i);
    if (serverMatch) serverSet.add(serverMatch[1].trim());

    const techMatches = clean.match(/\b(?:Cloudflare|WordPress|PHP|Apache|nginx|jQuery|Bootstrap|MySQL|Drupal|Joomla|IIS|OpenResty|LiteSpeed)\b/gi);
    if (techMatches) {
      techMatches.forEach(t => techSet.add(t));
    }

    const bracketMatches = clean.match(/[A-Za-z0-9.+_-]+\[[^\]]+\]/g) || [];
    bracketMatches.forEach(token => {
      if (!/^https?:\/\//i.test(token) &&
          !/^IP\[/i.test(token) &&
          !/^Title\[/i.test(token) &&
          !/^Country\[/i.test(token) &&
          !/^HTTPServer\[/i.test(token) &&
          !/^UncommonHeaders\[/i.test(token) &&
          !/^X-Frame-Options\[/i.test(token)) {
        techSet.add(token);
      }
    });
  });

  data.urls = [...urlSet];
  data.ips = [...ipSet];
  data.titles = [...titleSet];
  data.servers = [...serverSet];
  data.technologies = [...techSet].slice(0, 20);

  return data;
}

function parseOutput(tool, lines) {
  const groups = [];
  const joined = lines.join('\n');

  // ── theHarvester (must check BEFORE WhatWeb — its URLs trigger WhatWeb detector) ──
  const isHarvester = lines.some(l => /\[\*\] Target:|\[\*\] Searching \w|\[\*\] Hosts found:|\[\*\] IPs found:|\[\*\] Emails found:/i.test(l));
  if (isHarvester) {
    const _hostRe = /^[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}$/;

    const emails = [...new Set(lines.flatMap(l =>
      l.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || []
    ))].filter(e => !e.includes('edge-security') && !e.includes('markmonitor'));

    const ips = [...new Set(lines.filter(l => {
      const t = l.trim();
      return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(t) || /^[0-9a-f:]+:[0-9a-f:]+$/i.test(t);
    }).map(l => l.trim()))];

    const hosts = [...new Set(lines
      .filter(l => {
        const t = l.trim();
        if (!t || t.startsWith('*') || t.startsWith('http') || t.startsWith('[') ||
            t.startsWith('-') || t.includes(' ') || t.includes('@') || t.includes('/')) return false;
        return _hostRe.test(t.split(':')[0].trim());
      })
      .map(l => l.trim().split(':')[0].trim())
    )];

    const asns = [...new Set(lines.filter(l => /^AS\d+$/.test(l.trim())).map(l => l.trim()))];
    const urls = [...new Set(lines.filter(l => /^https?:\/\//.test(l.trim())).map(l => l.trim()))];

    if (emails.length) groups.push({ title: `Emails (${emails.length})`, icon: '✉️', type: 'email', items: emails });
    if (ips.length)    groups.push({ title: `IPs (${ips.length})`, icon: '📡', type: 'ip', items: ips });
    if (hosts.length)  groups.push({ title: `Hosts / Subdominios (${hosts.length})`, icon: '🌐', type: 'host', items: hosts });
    if (urls.length)   groups.push({ title: `URLs interesantes (${urls.length})`, icon: '🔗', type: 'url', items: urls });
    if (asns.length)   groups.push({ title: `ASNs (${asns.length})`, icon: '🏢', type: 'generic', items: asns });

    if (groups.length) return groups;
  }

  // ── WHOIS (discover) ─────────────────────────────────────────────────────
  const isWhoisOutput = /Domain Name:|Registrar:|Name Server:|WHOIS/i.test(joined);

  if (isWhoisOutput && tool === 'discover') {

    const getAll = (regex) =>
      [...joined.matchAll(regex)].map(m => m[1].trim());

    const domain    = getAll(/Domain Name:\s*([^\n]+)/gi);
    const registrar = getAll(/Registrar:\s*([^\n]+)/gi);
    const creation  = getAll(/Creation Date:\s*([^\n]+)/gi);
    const expiry = getAll(/(?:Expiry Date|Expiration Date|Registry Expiry Date|Registrar Registration Expiration Date):\s*([^\n]+)/gi);

    const org       = getAll(/Registrant Organization:\s*([^\n]+)/gi);
    const country   = getAll(/Registrant Country:\s*([^\n]+)/gi);

    const nameservers = getAll(/Name Server:\s*([^\n]+)/gi)
      .map(ns => ns.toLowerCase());

    const status = getAll(/Domain Status:\s*([^\n]+)/gi);

    const emails = [...new Set(
      joined.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || []
    )];

    const whoisItems = [];

    if (domain.length)    whoisItems.push(`Dominio: ${domain[0]}`);
    if (registrar.length) whoisItems.push(`Registrador: ${registrar[0]}`);
    if (org.length)       whoisItems.push(`Organización: ${org[0]}`);
    if (country.length)   whoisItems.push(`País: ${country[0]}`);
    if (creation.length)  whoisItems.push(`Creado: ${creation[0]}`);
    if (expiry.length)    whoisItems.push(`Expira: ${expiry[0]}`);

    if (whoisItems.length) {
      groups.push({
        title: 'Resumen WHOIS',
        icon: '📇',
        type: 'generic',
        items: whoisItems
      });
    }

    if (nameservers.length) {
      groups.push({
        title: `Name Servers (${nameservers.length})`,
        icon: '🧭',
        type: 'host',
        items: [...new Set(nameservers)]
      });
    }

    if (emails.length) {
      groups.push({
        title: `Emails (${emails.length})`,
        icon: '✉️',
        type: 'email',
        items: emails
      });
    }

    if (status.length) {
      groups.push({
        title: 'Estados del dominio',
        icon: '🛡️',
        type: 'generic',
        items: [...new Set(status)]
      });
    }

    return groups;
  }

  // ── WhatWeb ──────────────────────────────────────────────────────────────
  const whatwebData = collectWhatWebData(lines);
  const looksLikeWhatWeb =
    whatwebData.urls.length ||
    whatwebData.ips.length ||
    whatwebData.titles.length ||
    whatwebData.servers.length;

  if (looksLikeWhatWeb && tool === 'discover') {
    if (whatwebData.urls.length) groups.push({ title: 'URLs analizadas', icon: '🔗', type: 'url', items: whatwebData.urls });
    if (whatwebData.ips.length) groups.push({ title: 'IPs detectadas', icon: '📡', type: 'ip', items: whatwebData.ips });
    if (whatwebData.titles.length) groups.push({ title: 'Títulos', icon: '📰', type: 'generic', items: whatwebData.titles });
    if (whatwebData.servers.length) groups.push({ title: 'Servidor web', icon: '🖥️', type: 'generic', items: whatwebData.servers });
    if (whatwebData.technologies.length) groups.push({ title: 'Tecnologías detectadas', icon: '🧩', type: 'generic', items: whatwebData.technologies });
    return groups;
  }

  // ── DNSRecon ─────────────────────────────────────────────────────────────
  const isDNSRecon = lines.some(l => /\[\*\]\s*(A|AAAA|MX|NS|TXT|SOA|CNAME|SRV|PTR|CAA)\b/i.test(l) ||
    /\[\+\] (DNS|Enumerating|Performing)/i.test(l));
  if (isDNSRecon) {
    const recTypes = { A: [], AAAA: [], MX: [], NS: [], TXT: [], SOA: [], CNAME: [], SRV: [], OTHER: [] };
    lines.forEach(line => {
      const m = line.match(/\[\*\]\s*(A|AAAA|MX|NS|TXT|SOA|CNAME|SRV|PTR|CAA)\s+(.+)/i);
      if (!m) return;
      const type = m[1].toUpperCase();
      const val  = m[2].trim();
      if (recTypes[type]) recTypes[type].push(val); else recTypes.OTHER.push(`${type} ${val}`);
    });
    const iconMap = { A:'📍', AAAA:'📍', MX:'📧', NS:'🧭', TXT:'📝', SOA:'🏛️', CNAME:'🔀', SRV:'⚙️', OTHER:'📋' };
    const titleMap = { A:'Registros A (IPv4)', AAAA:'Registros AAAA (IPv6)', MX:'Registros MX (correo)',
      NS:'Nameservers (NS)', TXT:'Registros TXT', SOA:'SOA', CNAME:'CNAME', SRV:'SRV', OTHER:'Otros registros' };
    const typeMap  = { A:'ip', AAAA:'ip', NS:'host', MX:'host', CNAME:'host', TXT:'generic', SOA:'generic', SRV:'generic', OTHER:'generic' };
    Object.entries(recTypes).forEach(([k, items]) => {
      if (items.length) groups.push({ title: titleMap[k], icon: iconMap[k], type: typeMap[k], items });
    });
    // also pick up IPs from the lines
    const ips = [...new Set(lines.flatMap(l => l.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))];
    if (ips.length) groups.push({ title: 'IPs mencionadas', icon: '📡', type: 'ip', items: ips });
    if (groups.length) return groups;
  }

  // ── Nmap ─────────────────────────────────────────────────────────────────
  const nmapPorts = lines.filter(l => /\d+\/(tcp|udp)\s+(open|closed|filtered)/i.test(l));
  if (nmapPorts.length) {
    const open     = nmapPorts.filter(l => /\s+open\s+/i.test(l));
    const filtered = nmapPorts.filter(l => /\s+filtered\s+/i.test(l));
    const closed   = nmapPorts.filter(l => /\s+closed\s+/i.test(l));
    if (open.length)     groups.push({ title: `Puertos abiertos (${open.length})`, icon: '🔓', type: 'port-open', items: open });
    if (filtered.length) groups.push({ title: `Puertos filtrados (${filtered.length})`, icon: '🔒', type: 'port-filtered', items: filtered });
    if (closed.length)   groups.push({ title: `Puertos cerrados (${closed.length})`, icon: '⛔', type: 'generic', items: closed });
    // Detect OS
    const os = lines.find(l => /OS details:|Running:|OS CPE:/i.test(l));
    if (os) groups.push({ title: 'Sistema operativo detectado', icon: '💻', type: 'generic', items: [os.replace(/^.*?:/,'').trim()] });
    const nmapIps = [...new Set(lines.flatMap(l => l.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))];
    if (nmapIps.length) groups.push({ title: 'IPs escaneadas', icon: '📡', type: 'ip', items: nmapIps });
    return groups;
  }

  // ── theHarvester handled at top of function ────────────────────────────

  // ── Amass ────────────────────────────────────────────────────────────────
  if (tool === 'amass') {
    const domRe = /^[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}$/;
    const fqdns = new Set();
    const ips   = new Set();
    const asns  = new Set();
    const nets  = new Set();

    lines.forEach(l => {
      // Graph format: extract all typed tokens — "value (TYPE)"
      for (const m of l.matchAll(/([^\s(]+)\s+\(FQDN\)/g))
        if (domRe.test(m[1])) fqdns.add(m[1]);
      for (const m of l.matchAll(/([\d.]+)\s+\(IPAddress\)/g))
        ips.add(m[1]);
      for (const m of l.matchAll(/(\d+)\s+\(ASN\)/g))
        asns.add(`AS${m[1]}`);
      for (const m of l.matchAll(/([^\s(]+\/\d+)\s+\(Netblock\)/g))
        nets.add(m[1]);
      // Plain subdomain lines (enum output without graph)
      const tok = l.trim().split(/\s/)[0];
      if (tok && domRe.test(tok)) fqdns.add(tok);
    });

    if (fqdns.size) groups.push({ title: `Hosts / Dominios (${fqdns.size})`, icon: '🌐', type: 'host', items: [...fqdns] });
    if (ips.size)   groups.push({ title: `IPs (${ips.size})`, icon: '📡', type: 'ip', items: [...ips] });
    if (asns.size)  groups.push({ title: `ASNs (${asns.size})`, icon: '🏢', type: 'generic', items: [...asns] });
    if (nets.size)  groups.push({ title: `Netblocks (${nets.size})`, icon: '🔗', type: 'generic', items: [...nets] });
    if (groups.length) return groups;
  }

  // ── Subfinder ────────────────────────────────────────────────────────────
  if (tool === 'subfinder') {
    const domRe = /^[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}$/;
    const subs = [...new Set(
      lines.map(l => l.trim()).filter(l => domRe.test(l) && !l.includes(' '))
    )].sort();
    if (subs.length) {
      groups.push({ title: `Subdominios (${subs.length})`, icon: '🌐', type: 'host', items: subs });
      return groups;
    }
  }

  // ── Katana ───────────────────────────────────────────────────────────────
  if (tool === 'katana') {
    const urls = [...new Set(lines.flatMap(l => l.match(/https?:\/\/[^\s]+/g) || []))];
    const jsUrls  = urls.filter(u => u.endsWith('.js'));
    const apiUrls = urls.filter(u => /\/api\/|\/v[0-9]+\//.test(u));
    const other   = urls.filter(u => !jsUrls.includes(u) && !apiUrls.includes(u));
    if (apiUrls.length) groups.push({ title: `Endpoints API (${apiUrls.length})`, icon: '⚡', type: 'url', items: apiUrls });
    if (jsUrls.length)  groups.push({ title: `Archivos JS (${jsUrls.length})`, icon: '📜', type: 'url', items: jsUrls });
    if (other.length)   groups.push({ title: `Rutas / URLs (${other.length})`, icon: '🔗', type: 'url', items: other });
    return groups;
  }

  // ── Sherlock ──────────────────────────────────────────────────────────────
  const isSherlock = tool === 'identidad' && lines.some(l => /Checking username .+ on:/i.test(l) || /Search completed with \d+ results/i.test(l));
  if (isSherlock) {
    const found = lines
      .map(l => l.match(/^\[.{0,2}\+.{0,2}\]\s+(.+?):\s+(https?:\/\/\S+)/i))
      .filter(Boolean)
      .map(m => `${m[1].trim()}: ${m[2].trim()}`);
    const totalMatch = joined.match(/Search completed with (\d+) results/i);
    const total = totalMatch ? parseInt(totalMatch[1]) : found.length;
    if (found.length) {
      groups.push({ title: `Perfiles encontrados (${total})`, icon: '👤', type: 'url', items: found });
    }
    if (groups.length) return groups;
  }

  // ── Blackbird ─────────────────────────────────────────────────────────────
  const isBlackbird = tool === 'identidad' && lines.some(l => /Enumerating accounts with username|by Lucas Antoniaci|Blackbird v\d/i.test(l) || /✔️.*\[/.test(l));
  if (isBlackbird) {
    const sitesFound = [];
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      if (!/✔️/.test(l)) continue;
      // Same line: ✔️  [Site] https://...
      const sameM = l.match(/\[([^\]]+)\]\s+(https?:\/\/\S+)/);
      if (sameM) { sitesFound.push(`${sameM[1]}: ${sameM[2]}`); continue; }
      // Multi-line: ✔️  [Site]\nhttps://...
      const siteM = l.match(/\[([^\]]+)\]/);
      const nextLine = (lines[i + 1] || '').trim();
      if (siteM && nextLine.startsWith('http')) {
        sitesFound.push(`${siteM[1]}: ${nextLine}`);
      } else if (siteM) {
        sitesFound.push(siteM[1]);
      }
    }
    const totalMatch = joined.match(/Check completed in ([\d.]+) seconds/i);
    const total = totalMatch ? ` en ${totalMatch[1]}s` : '';
    if (sitesFound.length) {
      groups.push({ title: `Perfiles encontrados (${sitesFound.length})${total}`, icon: '🐦', type: 'url', items: sitesFound });
    }
    if (groups.length) return groups;
  }

  // ── WafW00f ───────────────────────────────────────────────────────────────
  const isWafw00f = /WAFW00F|Checking https?:\/\/|No WAF detected|is behind .+ WAF|The site .+ is behind/i.test(joined);
  if (isWafw00f && tool === 'discover') {
    const wafLines = lines.filter(l => /\[\+\].*(?:WAF|Generic Detection|behind)/i.test(l) || /No WAF detected/i.test(l));
    const wafItems = wafLines.map(l => l.replace(/\[\+\]\s*|\[\-\]\s*/g, '').trim()).filter(Boolean);
    if (!wafItems.length) wafItems.push(lines.find(l => /No WAF detected/i.test(l)) ? 'No WAF detectado' : 'Resultado no determinado');
    groups.push({ title: 'Detección WAF', icon: '🛡️', type: 'generic', items: wafItems });
    const wafIps = [...new Set(lines.flatMap(l => l.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))];
    if (wafIps.length) groups.push({ title: 'IPs detectadas', icon: '📡', type: 'ip', items: wafIps });
    return groups;
  }

  // ── sslscan ───────────────────────────────────────────────────────────────
  const isSslscan = /Testing SSL server|SSLv2\s+(enabled|disabled)|TLSv1\.\d\s+(enabled|disabled)|Heartbleed/i.test(joined);
  if (isSslscan && tool === 'discover') {
    const protocols = [];
    lines.forEach(l => {
      const m = l.match(/(SSLv\d|TLSv\d(?:\.\d)?)\s+(enabled|disabled)/i);
      if (m) protocols.push(`${m[1]}: ${m[2]}`);
    });
    if (protocols.length) groups.push({ title: 'Protocolos SSL/TLS', icon: '🔐', type: 'generic', items: protocols });
    const certLines = lines.filter(l => /^\s*(Subject|Issuer|Not valid|Signature Algorithm|Altnames)/i.test(l)).map(l => l.trim());
    if (certLines.length) groups.push({ title: 'Certificado', icon: '📜', type: 'generic', items: certLines });
    const vulnLines = lines.filter(l => /vulnerable|heartbleed|POODLE|ROBOT|DROWN|BREACH/i.test(l)).map(l => l.trim());
    if (vulnLines.length) groups.push({ title: 'Vulnerabilidades TLS', icon: '⚠️', type: 'generic', items: vulnLines });
    const sslIps = [...new Set(lines.flatMap(l => l.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))];
    if (sslIps.length) groups.push({ title: 'IPs', icon: '📡', type: 'ip', items: sslIps });
    if (groups.length) return groups;
  }

  // ── sslyze ────────────────────────────────────────────────────────────────
  const isSslyze = /sslyze|CHECKING HOST|SSL 2\.0 Cipher|TLS 1\.[0-9] Cipher|Certificate Information/i.test(joined);
  if (isSslyze && tool === 'discover') {
    const tlsEnabled = [...new Set(lines.filter(l => /TLS \d\.\d Cipher suites/i.test(l)).map(l => {
      const m = l.match(/TLS (\d\.\d)/i); return m ? `TLS ${m[1]}: soportado` : null;
    }).filter(Boolean))];
    const tlsDisabled = lines.filter(l => /SSL 2\.0|SSL 3\.0/.test(l) && /rejected|not support/i.test(joined)).map(l => l.trim());
    if (tlsEnabled.length) groups.push({ title: 'Protocolos TLS soportados', icon: '🔐', type: 'generic', items: tlsEnabled });
    const vulns = lines.filter(l => /VULNERABLE|Heartbleed|ROBOT|FALLBACK/i.test(l)).map(l => l.trim().replace(/^\*\s*/, ''));
    if (vulns.length) groups.push({ title: 'Vulnerabilidades', icon: '⚠️', type: 'generic', items: vulns });
    const certInfo = lines.filter(l => /Subject:|Issuer:|Not Before|Not After|SHA-|Signature/i.test(l)).map(l => l.trim().replace(/^\s*/, ''));
    if (certInfo.length) groups.push({ title: 'Certificado', icon: '📜', type: 'generic', items: certInfo });
    if (groups.length) return groups;
  }

  // ── Nikto ─────────────────────────────────────────────────────────────────
  const isNikto = /Nikto v\d|Target IP:|Target Hostname:|OSVDB-\d|requests: \d/i.test(joined);
  if (isNikto && tool === 'discover') {
    const findings = lines.filter(l => /^\+ /.test(l) && !/^\+ (Target IP|Target Hostname|Target Port|End Time|Start Time|Server:)/i.test(l)).map(l => l.replace(/^\+\s*/, '').trim());
    const server = lines.find(l => /^\+ Server:/i.test(l));
    const targetIp = lines.find(l => /^\+ Target IP:/i.test(l));
    const info = [];
    if (targetIp) info.push(targetIp.replace(/^\+\s*/, '').trim());
    if (server) info.push(server.replace(/^\+\s*/, '').trim());
    if (info.length) groups.push({ title: 'Objetivo', icon: '🎯', type: 'generic', items: info });
    if (findings.length) groups.push({ title: `Hallazgos (${findings.length})`, icon: '⚠️', type: 'generic', items: findings });
    const niktoIps = [...new Set(lines.flatMap(l => l.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))];
    if (niktoIps.length) groups.push({ title: 'IPs', icon: '📡', type: 'ip', items: niktoIps });
    if (groups.length) return groups;
  }

  // ── Holehe ────────────────────────────────────────────────────────────────
  const isHolehe = tool === 'identidad' && /websites checked|Email used|holehe/i.test(joined);
  if (isHolehe) {
    const registered = lines.filter(l => /^\[\+\]\s+\S/.test(l) && !/Email used|Email not used|Rate limit/i.test(l)).map(l => {
      const m = l.match(/^\[\+\]\s+(.+)/); return m ? m[1].trim() : null;
    }).filter(Boolean);
    if (registered.length) groups.push({ title: `Servicios con cuenta registrada (${registered.length})`, icon: '📧', type: 'generic', items: registered });
    if (groups.length) return groups;
  }

  // ── Maigret ───────────────────────────────────────────────────────────────
  const isMaigret = tool === 'identidad' && /Maigret database|Starting a search|Checking username .+ on:/i.test(joined);
  if (isMaigret) {
    const found = [];
    lines.forEach(l => {
      const m = l.match(/\[\+\]\s+([^:]+):\s+(https?:\/\/\S+)/);
      if (m) found.push(`${m[1].trim()}: ${m[2].trim()}`);
    });
    if (found.length) groups.push({ title: `Perfiles encontrados (${found.length})`, icon: '🔍', type: 'url', items: found });
    if (groups.length) return groups;
  }

  // ── usufy / searchfy (OSRFramework) ──────────────────────────────────────
  const isOSRF = tool === 'identidad' && /i3visio|OSRFramework|platform.*url|query.*results/i.test(joined);
  if (isOSRF) {
    const urlItems = [...new Set(lines.flatMap(l => l.match(/https?:\/\/\S+/g) || []))];
    if (urlItems.length) groups.push({ title: `Perfiles / resultados (${urlItems.length})`, icon: '🔗', type: 'url', items: urlItems });
    if (groups.length) return groups;
  }

  // ── Shodan CLI ────────────────────────────────────────────────────────────
  if (tool === 'shodancli') {
    // shodan count → single number output
    const nonEmpty = lines.map(l => l.trim()).filter(Boolean);
    if (nonEmpty.length <= 3 && /^\d+$/.test(nonEmpty[0])) {
      groups.push({ title: 'Total activos indexados en Shodan', icon: '🔢', type: 'generic', items: [nonEmpty[0]] });
      return groups;
    }
    const shodanIps = [...new Set(lines.flatMap(l => l.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))];
    const shodanPorts = [...new Set(lines.flatMap(l => l.match(/\b\d{2,5}\/(?:tcp|udp)\b/g) || []))];
    const shodanHosts = [...new Set(lines.filter(l => /Hostnames?:/i.test(l)).flatMap(l => {
      const m = l.match(/Hostnames?:\s*(.+)/i); return m ? m[1].split(',').map(h => h.trim()) : [];
    }).filter(Boolean))];
    const shodanCves = [...new Set(lines.flatMap(l => l.match(/CVE-\d{4}-\d+/g) || []))];
    const shodanInfo = lines.filter(l => /^(Country|Organization|ISP|OS|City|ASN):/i.test(l.trim())).map(l => l.trim());
    if (shodanInfo.length) groups.push({ title: 'Información del host', icon: '🏢', type: 'generic', items: shodanInfo });
    if (shodanIps.length) groups.push({ title: `IPs (${shodanIps.length})`, icon: '📡', type: 'ip', items: shodanIps });
    if (shodanPorts.length) groups.push({ title: `Puertos (${shodanPorts.length})`, icon: '🔌', type: 'port-open', items: shodanPorts });
    if (shodanHosts.length) groups.push({ title: `Hostnames (${shodanHosts.length})`, icon: '🌐', type: 'host', items: shodanHosts });
    if (shodanCves.length) groups.push({ title: `CVEs (${shodanCves.length})`, icon: '⚠️', type: 'generic', items: shodanCves });
    // shodan search tabular output: ip_str,port,org,...
    const tabRows = lines.filter(l => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d+/.test(l.trim())).map(l => l.trim());
    if (tabRows.length && !shodanIps.length) groups.push({ title: `Resultados (${tabRows.length})`, icon: '📋', type: 'generic', items: tabRows });
    if (groups.length) return groups;
  }

  // ── FinalRecon ────────────────────────────────────────────────────────────
  if (tool === 'webrecon' && /FinalRecon|Banner Grab|SSL Info|DNS Enum|Subdomain Enum/i.test(joined)) {
    const freDomRe = /^[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}$/;
    const freIps = [...new Set(lines.flatMap(l => l.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))];
    const freSubs = [...new Set(lines.flatMap(l => l.match(/\b[a-zA-Z0-9][\w.\-]*\.[a-zA-Z]{2,}\b/g) || []).filter(h => freDomRe.test(h)))];
    const freHeaders = lines.filter(l => /^(Server|X-|Content-|Strict-|Access-Control|Set-Cookie)/i.test(l.trim())).map(l => l.trim());
    const freInfo = lines.filter(l => /^\[.+\]/.test(l.trim()) && l.length < 120).map(l => l.trim());
    if (freIps.length) groups.push({ title: `IPs (${freIps.length})`, icon: '📡', type: 'ip', items: freIps });
    if (freSubs.length) groups.push({ title: `Dominios / Subdominios (${freSubs.length})`, icon: '🌐', type: 'host', items: freSubs });
    if (freHeaders.length) groups.push({ title: 'Cabeceras HTTP', icon: '📋', type: 'generic', items: freHeaders });
    if (freInfo.length) groups.push({ title: 'Información recopilada', icon: '📰', type: 'generic', items: freInfo.slice(0, 30) });
    if (groups.length) return groups;
  }

  // ── httpx (discover) ─────────────────────────────────────────────────────
  // Output: https://domain.com [STATUS] [TITLE] [SERVER] [TECH] [IP]
  const isHttpx = tool === 'discover' && lines.some(l => /^https?:\/\/\S+\s+\[\d{3}\]/.test(l));
  if (isHttpx) {
    const httpxLines = lines.filter(l => /^https?:\/\/\S+\s+\[\d{3}\]/.test(l));
    const hosts = [], techs = new Set(), ips = new Set();
    httpxLines.forEach(l => {
      const urlM = l.match(/^(https?:\/\/\S+)/);
      const codeM = l.match(/\[(\d{3})\]/);
      const titleM = l.match(/\[(\d{3})\][^\[]*\[([^\]]+)\]/);
      const ipM = l.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
      const techMs = [...l.matchAll(/\[([A-Za-z][^\]]{1,40})\]/g)].slice(2).map(m => m[1]);
      if (urlM && codeM) {
        const title = titleM ? titleM[2] : '';
        hosts.push(`${urlM[1]} [${codeM[1]}]${title ? ' — ' + title : ''}`);
      }
      if (ipM) ips.add(ipM[1]);
      techMs.forEach(t => { if (!/^\d+$/.test(t)) techs.add(t); });
    });
    if (hosts.length)  groups.push({ title: `Hosts HTTP (${hosts.length})`, icon: '🌐', type: 'url', items: hosts });
    if (ips.size)      groups.push({ title: `IPs (${ips.size})`, icon: '📡', type: 'ip', items: [...ips] });
    if (techs.size)    groups.push({ title: `Tecnologías (${techs.size})`, icon: '🧩', type: 'generic', items: [...techs] });
    if (groups.length) return groups;
  }

  // ── dnsx (discover) ───────────────────────────────────────────────────────
  // Output: domain.com [A] [1.2.3.4]
  const isDnsx = tool === 'discover' && lines.some(l => /\[(A|AAAA|MX|NS|TXT|CNAME|SOA)\]/.test(l));
  if (isDnsx) {
    const byType = { A: [], AAAA: [], MX: [], NS: [], TXT: [], CNAME: [], OTHER: [] };
    lines.forEach(l => {
      const m = l.match(/\[(A|AAAA|MX|NS|TXT|CNAME|SOA|CAA|SRV)\]\s*\[([^\]]+)\]/i);
      if (!m) return;
      const type = m[1].toUpperCase(), val = m[2].trim();
      (byType[type] || byType.OTHER).push(val);
    });
    const iconMap = { A:'📍', AAAA:'📍', MX:'📧', NS:'🧭', TXT:'📝', CNAME:'🔀', OTHER:'📋' };
    const titleMap = { A:'Registros A (IPv4)', AAAA:'Registros AAAA (IPv6)', MX:'Registros MX', NS:'Nameservers', TXT:'Registros TXT', CNAME:'CNAME', OTHER:'Otros' };
    Object.entries(byType).forEach(([k, items]) => {
      if (items.length) groups.push({ title: titleMap[k], icon: iconMap[k], type: k==='A'||k==='AAAA'?'ip':k==='NS'||k==='CNAME'||k==='MX'?'host':'generic', items: [...new Set(items)] });
    });
    if (groups.length) return groups;
  }

  // ── Nuclei ────────────────────────────────────────────────────────────────
  if (tool === 'nuclei') {
    // Format: [template-id] [type] [severity] URL [info]
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sevIcon  = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: 'ℹ️' };
    const sevGroups = {};
    lines.forEach(l => {
      const m = l.match(/\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[(critical|high|medium|low|info)\]\s*(\S+)/i);
      if (!m) return;
      const [, tmpl, type, sev, url] = m;
      const key = sev.toLowerCase();
      if (!sevGroups[key]) sevGroups[key] = [];
      sevGroups[key].push(`${tmpl} (${type}) → ${url}`);
    });
    Object.keys(sevGroups).sort((a, b) => (sevOrder[a]??9) - (sevOrder[b]??9)).forEach(sev => {
      const items = sevGroups[sev];
      groups.push({ title: `${sevIcon[sev] || '▪'} ${sev.charAt(0).toUpperCase()+sev.slice(1)} (${items.length})`, icon: sevIcon[sev] || '▪', type: 'generic', items });
    });
    const nucleiIps = [...new Set(lines.flatMap(l => l.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))];
    if (nucleiIps.length) groups.push({ title: 'IPs', icon: '📡', type: 'ip', items: nucleiIps });
    if (groups.length) return groups;
  }

  // ── URL Discovery (gau / waybackurls) ────────────────────────────────────
  if (tool === 'urls') {
    const allUrls = [...new Set(lines.map(l => l.trim()).filter(l => /^https?:\/\//.test(l)))];
    const js    = allUrls.filter(u => /\.js(\?|$)/.test(u));
    const api   = allUrls.filter(u => /\/api\/|\/v\d+\/|graphql/i.test(u));
    const params = allUrls.filter(u => u.includes('?') && !js.includes(u) && !api.includes(u));
    const other  = allUrls.filter(u => !js.includes(u) && !api.includes(u) && !params.includes(u));
    if (api.length)    groups.push({ title: `Endpoints API (${api.length})`, icon: '⚡', type: 'url', items: api });
    if (js.length)     groups.push({ title: `Archivos JS (${js.length})`, icon: '📜', type: 'url', items: js });
    if (params.length) groups.push({ title: `URLs con parámetros (${params.length})`, icon: '🔍', type: 'url', items: params });
    if (other.length)  groups.push({ title: `Rutas / URLs (${other.length})`, icon: '🔗', type: 'url', items: other });
    if (groups.length) return groups;
  }

  // ── Generic fallback ─────────────────────────────────────────────────────
  const emails = [...new Set(lines.flatMap(l => l.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || []))];
  if (emails.length) groups.push({ title: 'Emails', icon: '✉️', type: 'email', items: emails });

  const ips = [...new Set(lines.flatMap(l => l.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))];
  if (ips.length) groups.push({ title: 'IPs', icon: '📡', type: 'ip', items: ips });

  const ports2 = lines.filter(l => /\d+\/(tcp|udp)\s+(open|closed|filtered)/i.test(l));
  if (ports2.length) groups.push({ title: 'Puertos', icon: '🔌', type: 'generic', items: ports2 });

  return groups;
}

// ── Structured JSON renderer (from backend parse_structured_json) ─────────────
function renderStructured(tool, data) {
  const groups = [];

  // ── theHarvester ────────────────────────────────────────────────────────
  if (data.tool === 'theharvester') {
    if (data.emails?.length)
      groups.push({ title: `Emails (${data.emails.length})`, icon: '✉️', type: 'email', items: data.emails });
    if (data.ips?.length)
      groups.push({ title: `IPs (${data.ips.length})`, icon: '📡', type: 'ip', items: data.ips });
    if (data.hosts?.length)
      groups.push({ title: `Hosts / Subdominios (${data.hosts.length})`, icon: '🌐', type: 'host', items: data.hosts });
    if (data.interesting_urls?.length)
      groups.push({ title: `URLs interesantes (${data.interesting_urls.length})`, icon: '🔗', type: 'url', items: data.interesting_urls });
    if (data.asns?.length)
      groups.push({ title: `ASNs (${data.asns.length})`, icon: '🏢', type: 'generic', items: data.asns });
  }

  // ── DNSRecon ────────────────────────────────────────────────────────────
  else if (data.tool === 'dnsrecon') {
    const iconMap = { A:'📍', AAAA:'📍', MX:'📧', NS:'🧭', TXT:'📝', SOA:'🏛️', CNAME:'🔀', SRV:'⚙️' };
    const typeMap  = { A:'ip', AAAA:'ip', NS:'host', MX:'host', CNAME:'host', TXT:'generic', SOA:'generic', SRV:'generic' };
    const labelMap = { A:'Registros A (IPv4)', AAAA:'Registros AAAA (IPv6)', MX:'Registros MX',
                       NS:'Nameservers', TXT:'Registros TXT', SOA:'SOA', CNAME:'CNAME', SRV:'SRV' };
    Object.entries(data.records || {}).forEach(([type, items]) => {
      if (items.length) groups.push({
        title: labelMap[type] || type,
        icon: iconMap[type] || '📋',
        type: typeMap[type] || 'generic',
        items
      });
    });
  }

  // ── Nmap ────────────────────────────────────────────────────────────────
  else if (data.tool === 'nmap') {
    if (data.ips?.length)
      groups.push({ title: `IPs escaneadas`, icon: '📡', type: 'ip', items: data.ips });
    if (data.ports_open?.length)
      groups.push({ title: `Puertos abiertos (${data.ports_open.length})`, icon: '🔓', type: 'port-open',
        items: data.ports_open.map(p => `${p.port}/${p.proto}   open   ${p.service}   ${p.version}`.trimEnd()) });
    if (data.ports_filtered?.length)
      groups.push({ title: `Puertos filtrados (${data.ports_filtered.length})`, icon: '🔒', type: 'port-filtered',
        items: data.ports_filtered.map(p => `${p.port}/${p.proto}   ${p.state}   ${p.service}`.trimEnd()) });
    if (data.os?.length)
      groups.push({ title: 'Sistema operativo', icon: '💻', type: 'generic', items: data.os });
  }

  // ── Amass ───────────────────────────────────────────────────────────────
  else if (data.tool === 'amass') {
    if (data.subdomains?.length)
      groups.push({ title: `Subdominios (${data.subdomains.length})`, icon: '🌐', type: 'host', items: data.subdomains });
    if (data.ips?.length)
      groups.push({ title: `IPs (${data.ips.length})`, icon: '📡', type: 'ip', items: data.ips });
  }

  if (groups.length) {
    renderParsed(tool, groups);
    return true;
  }
  return false;
}


function _renderPortTable(items) {
  const rows = items.map(line => {
    // e.g. "80/tcp   open  http    Apache httpd 2.4"
    const m = line.match(/(\d+)\/(tcp|udp)\s+(\w+)\s*(\S*)\s*(.*)/i);
    if (!m) return `<tr><td colspan="4">${escHtml(line)}</td></tr>`;
    const [, port, proto, state, svc, version] = m;
    const stateCls = state === 'open' ? 'port-open-row' : 'port-filtered-row';
    return `<tr class="${stateCls}">
      <td class="pt-port">${escHtml(port)}/${escHtml(proto)}</td>
      <td class="pt-state">${escHtml(state)}</td>
      <td class="pt-svc">${escHtml(svc)}</td>
      <td class="pt-ver">${escHtml(version)}</td>
    </tr>`;
  }).join('');
  return `<table class="port-table"><thead><tr>
    <th>Puerto</th><th>Estado</th><th>Servicio</th><th>Versión</th>
  </tr></thead><tbody>${rows}</tbody></table>`;
}

function renderParsed(tool, groups) {
  const container = $(`results-${tool}`);
  if (!container) return;

  if (!groups.length) {
    container.innerHTML = makeInfoText(UI_TEXT.emptyStructured);
    return;
  }

  container.innerHTML = groups.map(group => {
    const isPortGroup = group.type === 'port-open' || group.type === 'port-filtered';
    const content = isPortGroup
      ? _renderPortTable(group.items)
      : `<div class="result-items">${group.items.map(item =>
          `<div class="result-item ${group.type}">${escHtml(item)}</div>`
        ).join('')}</div>`;
    return `
    <div class="result-group">
      <div class="rg-title">
        ${group.icon} ${group.title}
        <span class="rg-count">${group.items.length}</span>
      </div>
      ${content}
    </div>`;
  }).join('');
}

function _rawLine(text) {
  if (!text) return '';
  const t = text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
  if (t.startsWith('⚠')) return `<span class="rl-err">${t}</span>\n`;
  if (t.startsWith('▶')) return `<span class="rl-cmd">${t}</span>\n`;
  if (t.startsWith('✖')) return `<span class="rl-err">${t}</span>\n`;
  if (/\d+\/(tcp|udp)\s+(open)/i.test(t)) return `<span class="rl-open">${t}</span>\n`;
  if (/\d+\/(tcp|udp)\s+(filtered|closed)/i.test(t)) return `<span class="rl-closed">${t}</span>\n`;
  if (/^\[\+\]|^\[INFO\]/i.test(t)) return `<span class="rl-info">${t}</span>\n`;
  if (/^\[!\]|^\[-\]|\bERROR\b|\bFAILED\b/i.test(t)) return `<span class="rl-warn">${t}</span>\n`;
  return t + '\n';
}

function createBufferedWriter(rawOutput) {
  let buffer = [];
  let timer = null;
  let lineCount = 0;

  function flush() {
    if (!rawOutput || !buffer.length) return;
    const html = buffer.map(_rawLine).join('');
    buffer = [];
    rawOutput.insertAdjacentHTML('beforeend', html);
    // count newlines added
    lineCount += (html.match(/\n/g) || []).length;
    rawOutput.scrollTop = rawOutput.scrollHeight;
    timer = null;
    // update line counter badge if present
    const badge = rawOutput.parentElement && rawOutput.parentElement.querySelector('.line-count-badge');
    if (badge) badge.textContent = `${lineCount} líneas`;
  }

  return {
    write(text) {
      // split multi-line text so each line gets colorized independently
      const lines = text.split('\n');
      lines.forEach(l => { if (l !== '') buffer.push(l); });
      if (!timer) timer = setTimeout(flush, 120);
    },
    flushNow() { clearTimeout(timer); timer = null; flush(); },
    reset() { if (rawOutput) rawOutput.innerHTML = ''; lineCount = 0; }
  };
}

function runTool(tool) {
  const input = $(`cmd-${tool}`);
  let cmd = input ? input.value.trim() : '';

  if (!cmd) {
    const idx = selectedSubtool[tool];
    if (idx === undefined) {
      setHtml(`results-${tool}`, makeInfoText(UI_TEXT.missingCommand, 'error'));
      return;
    }
    cmd = SUBTOOLS[tool][idx].cmd(target || 'OBJETIVO');
  }

  if (cmd.includes('OBJETIVO')) {
    setHtml(`results-${tool}`, makeInfoText(UI_TEXT.missingTarget, 'error'));
    return;
  }

  const rawOutput = $(`raw-out-${tool}`);
  if (rawOutput) rawOutput.innerHTML = '';

  const writer = createBufferedWriter(rawOutput);

  setStatus(tool, 'running');
  if ($(`run-${tool}`)) $(`run-${tool}`).disabled = true;
  if ($(`stop-${tool}`)) $(`stop-${tool}`).style.display = 'inline-block';
  setHtml(`results-${tool}`, makeInfoText(UI_TEXT.running));

  const allLines = [];
  let hadError = false;

  const requestId = crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random());
  runningRequests[tool] = requestId;

  streamCmd(
    cmd,
    requestId,
    (msg) => {

      if (msg.type === 'heartbeat') return;

      if (msg.type === 'start') {
        writer.write(`▶ ${msg.message}\n`);
        return;
      }

      if (msg.type === 'line') {
        if (msg.stream === 'stderr') {
          writer.write(`⚠ ${msg.message}\n`);
        } else {
          allLines.push(msg.message);
          writer.write(`${msg.message}\n`);
        }
        return;
      }

      if (msg.type === 'exit') {
        hadError = true;
        writer.write(`✖ Process finished with code ${msg.message}\n`);
        return;
      }

      if (msg.type === 'error') {
        hadError = true;
        writer.write(`✖ ${msg.message}\n`);
        return;
      }

      if (msg.type === 'structured') {
        _structuredCache[tool] = msg.data;
        return;
      }

      if (msg.type === 'done') {
        writer.flushNow();

        if (hadError) {
          if ($(`sr-${tool}`)) $(`sr-${tool}`).style.display = 'none';
          if ($(`sd-${tool}`)) $(`sd-${tool}`).style.display = 'none';

          const idle = $(`ss-${tool}`);
          if (idle) {
            idle.style.display = 'inline';
            idle.textContent = '✖ Error';
          }

          resetBtn(tool);
          delete runningRequests[tool];
          return;
        }

        setStatus(tool, 'done');

        const structured = _structuredCache[tool];
        delete _structuredCache[tool];

        if (structured && renderStructured(tool, structured)) {
          // rendered from JSON
        } else {
          const parsed = parseOutput(tool, allLines);
          if (parsed.length) renderParsed(tool, parsed);
          else setHtml(`results-${tool}`, makeInfoText(UI_TEXT.emptyStructured));
        }

        resetBtn(tool);
        delete runningRequests[tool];
        saveHistory(tool);
        const dlBtn = $(`dl-btn-${tool}`);
        if (dlBtn) dlBtn.style.display = 'inline-flex';
      }
    },
    (err) => {
      writer.flushNow();
      setHtml(`results-${tool}`, makeInfoText(`Error de conexión: ${err}`, 'error'));
      resetBtn(tool);
      delete runningRequests[tool];
    }
  );
}

// ── Parallel mode state ──────────────────────────────────────────────────────
const _parallelState = {}; // key: "tool-idx" → { startTime, done, lines, structured }
let _parallelTotal     = 0;
let _parallelDone      = 0;
let _parallelTimer     = null;
let _queuedIPs            = new Set();
let _ipAnalysisPending    = 0;
let _ipFindings           = [];
let _lastManualAnalysisId = null;
const _parallelRequestIds  = new Set(); // request_ids activos del modo paralelo
const _parallelControllers = new Map(); // requestId → AbortController

function _parallelKey(tool, idx) { return `${tool}-${idx}`; }

function _startParallelTimer() {
  if (_parallelTimer) clearInterval(_parallelTimer);
  _parallelTimer = setInterval(_updateParallelSummaryTimers, 500);
}

function _stopParallelTimer() {
  if (_parallelTimer) { clearInterval(_parallelTimer); _parallelTimer = null; }
}

function _updateParallelSummaryTimers() {
  Object.entries(_parallelState).forEach(([key, state]) => {
    if (state.done) return;
    const el = document.getElementById(`psum-timer-${key}`);
    if (el) el.textContent = _fmtSecs(Math.floor((Date.now() - state.startTime) / 1000));
  });
}

function _notifyParallelDone() {
  if (Notification.permission === 'granted') {
    new Notification('Aletheia — Modo paralelo', {
      body: `${_parallelTotal} herramientas completadas`,
      icon: '/favicon.ico'
    });
  }
}

function togglePsCard(cardId) {
  const card = document.getElementById(cardId);
  if (!card) return;
  card.classList.toggle('ps-collapsed');
}

function _parallelGroups(state) {
  // Returns groups array (same format as parseOutput) from state
  if (state.structured) {
    const d = state.structured;
    const groups = [];
    if (d.tool === 'theharvester') {
      if (d.emails?.length)           groups.push({ title: `Emails (${d.emails.length})`, icon: '✉️', type: 'email', items: d.emails });
      if (d.ips?.length)              groups.push({ title: `IPs (${d.ips.length})`, icon: '📡', type: 'ip', items: d.ips });
      if (d.hosts?.length)            groups.push({ title: `Hosts / Subdominios (${d.hosts.length})`, icon: '🌐', type: 'host', items: d.hosts });
      if (d.interesting_urls?.length) groups.push({ title: `URLs interesantes (${d.interesting_urls.length})`, icon: '🔗', type: 'url', items: d.interesting_urls });
      if (d.asns?.length)             groups.push({ title: `ASNs (${d.asns.length})`, icon: '🏢', type: 'generic', items: d.asns });
    } else if (d.tool === 'dnsrecon') {
      const iconMap  = { A:'📍', AAAA:'📍', MX:'📧', NS:'🧭', TXT:'📝', SOA:'🏛️', CNAME:'🔀', SRV:'⚙️' };
      const typeMap  = { A:'ip', AAAA:'ip', NS:'host', MX:'host', CNAME:'host', TXT:'generic', SOA:'generic', SRV:'generic' };
      const labelMap = { A:'Registros A (IPv4)', AAAA:'Registros AAAA (IPv6)', MX:'Registros MX', NS:'Nameservers', TXT:'Registros TXT', SOA:'SOA', CNAME:'CNAME', SRV:'SRV' };
      Object.entries(d.records || {}).forEach(([type, items]) => {
        if (items.length) groups.push({ title: labelMap[type] || type, icon: iconMap[type] || '📋', type: typeMap[type] || 'generic', items });
      });
    } else if (d.tool === 'nmap') {
      if (d.ips?.length)              groups.push({ title: 'IPs escaneadas', icon: '📡', type: 'ip', items: d.ips });
      if (d.ports_open?.length)       groups.push({ title: `Puertos abiertos (${d.ports_open.length})`, icon: '🔓', type: 'port-open',
        items: d.ports_open.map(p => `${p.port}/${p.proto}   open   ${p.service}   ${p.version}`.trimEnd()) });
      if (d.ports_filtered?.length)   groups.push({ title: `Puertos filtrados (${d.ports_filtered.length})`, icon: '🔒', type: 'port-filtered',
        items: d.ports_filtered.map(p => `${p.port}/${p.proto}   ${p.state}   ${p.service}`.trimEnd()) });
      if (d.os?.length)               groups.push({ title: 'Sistema operativo', icon: '💻', type: 'generic', items: d.os });
    } else if (d.tool === 'amass') {
      if (d.subdomains?.length) groups.push({ title: `Subdominios (${d.subdomains.length})`, icon: '🌐', type: 'host', items: d.subdomains });
      if (d.ips?.length)        groups.push({ title: `IPs (${d.ips.length})`, icon: '📡', type: 'ip', items: d.ips });
    }
    return groups;
  }

  // Text-based fallback
  if (!state.allLines || !state.allLines.length) return [];
  return parseOutput(state.tool, state.allLines);
}

function _renderGroupsHtml(groups) {
  if (!groups.length) return '<p class="ps-empty">Sin resultados encontrados.</p>';
  return groups.map(group => {
    const isPortGroup = group.type === 'port-open' || group.type === 'port-filtered';
    const scrollCls = group.items.length > 8 ? 'ps-body-scroll' : '';
    const content = isPortGroup
      ? `<div class="${scrollCls}">${_renderPortTable(group.items)}</div>`
      : `<div class="result-items ${scrollCls}">${group.items.map(item =>
          `<div class="result-item ${group.type}">${escHtml(item)}</div>`
        ).join('')}</div>`;
    return `<div class="result-group">
      <div class="rg-title">${group.icon} ${escHtml(group.title)}<span class="rg-count">${group.items.length}</span></div>
      ${content}
    </div>`;
  }).join('');
}

const _GRP_SEV = {
  credential:'critical', leak:'critical',
  email:'medium', 'port-open':'high',
  host:'info', ip:'info', url:'info', generic:'info', 'port-filtered':'info',
};
const _GRP_SEV_COLOR = { critical:'#ef4444', high:'#f97316', medium:'#eab308', info:'#60a5fa' };
const _GRP_SEV_BG    = { critical:'rgba(239,68,68,.1)', high:'rgba(249,115,22,.1)', medium:'rgba(234,179,8,.1)', info:'rgba(96,165,250,.1)' };
const _GRP_SEV_LABEL = { critical:'CRÍTICO', high:'ALTO', medium:'MEDIO', info:'INFO' };
const _GRP_ASSET_ICON = { email:'📧', host:'🌐', ip:'🖥️', url:'🔗', credential:'⚠️', leak:'⚠️', 'port-open':'🖥️', 'port-filtered':'🖥️' };

function _groupItemTitle(type, item) {
  switch(type) {
    case 'email':         return `Email expuesto: ${item}`;
    case 'host':          return `Subdominio encontrado: ${item}`;
    case 'ip':            return `IP encontrada: ${item}`;
    case 'url':           return `URL expuesta: ${item}`;
    case 'port-open':     return `Puerto abierto: ${item}`;
    case 'port-filtered': return `Puerto filtrado: ${item}`;
    case 'credential':    return `Credencial expuesta: ${item}`;
    case 'leak':          return `Fuga detectada: ${item}`;
    default:              return item;
  }
}

function _groupItemRec(type) {
  switch(type) {
    case 'credential':
    case 'leak':      return 'Cambiar credenciales inmediatamente y revisar accesos no autorizados.';
    case 'email':     return 'Monitorizar este email en servicios de brechas (HaveIBeenPwned) y limitar exposición.';
    case 'port-open': return 'Revisar si este servicio es necesario externamente y aplicar control de acceso perimetral.';
    default:          return '';
  }
}

function _groupsAsFindingCards(groups, toolName, target) {
  if (!groups.length) return '<p class="ps-empty">Sin resultados encontrados.</p>';
  const toolColor = (TOOL_COLORS[toolName] || {}).color || '#9A6055';
  // Light-theme severity colors (darker than dark-mode versions)
  const _SEV_COLOR_LT = { critical:'#dc2626', high:'#ea580c', medium:'#ca8a04', info:'#2563eb' };
  const _SEV_BG_LT    = { critical:'rgba(220,38,38,.12)', high:'rgba(234,88,12,.12)', medium:'rgba(202,138,4,.12)', info:'rgba(37,99,235,.1)' };

  let html = '';
  groups.forEach(group => {
    const sev      = _GRP_SEV[group.type] || 'info';
    const sevColor = _SEV_COLOR_LT[sev];
    const sevBg    = _SEV_BG_LT[sev];
    const sevLabel = _GRP_SEV_LABEL[sev];
    const aIcon    = _GRP_ASSET_ICON[group.type] || '▶';
    const isPort   = group.type === 'port-open' || group.type === 'port-filtered';

    html += `<div style="font-size:.65rem;font-weight:800;text-transform:uppercase;letter-spacing:.1em;color:var(--text3);margin:1rem 0 .4rem;padding-bottom:.3rem;border-bottom:1px solid var(--ghost)">${group.icon} ${escHtml(group.title)}</div>`;

    group.items.forEach(item => {
      const asset      = isPort ? (target || toolName) : item;
      const assetShort = asset.length > 32 ? asset.slice(0, 30) + '…' : asset;
      const title      = _groupItemTitle(group.type, item);
      const rec        = _groupItemRec(group.type);
      const uid        = 'mc_' + Math.random().toString(36).slice(2);
      const analyzeBtn = group.type === 'ip'
        ? `<button onclick="event.stopPropagation();window._runIPPipeline&&window._runIPPipeline('${item}')"
             title="Analizar IP en pipeline (nmap + shodan + virustotal)"
             style="font-size:.6rem;font-weight:700;padding:.15rem .5rem;border-radius:.25rem;border:1px solid rgba(37,99,235,.35);background:rgba(37,99,235,.08);color:#2563eb;cursor:pointer;flex-shrink:0;white-space:nowrap;line-height:1.4">⚡ Analizar</button>`
        : '';
      html += `<div style="border-radius:.45rem;background:var(--bg-elev-3);border:1px solid var(--ghost);border-left:3px solid ${sevColor};margin-bottom:.4rem;overflow:hidden">
  <div style="display:flex;align-items:center;gap:.6rem;padding:.6rem .9rem;cursor:pointer;user-select:none" onclick="const b=document.getElementById('${uid}');b.style.display=b.style.display==='block'?'none':'block'">
    <span style="font-size:.64rem;font-weight:800;padding:.15rem .5rem;border-radius:.25rem;text-transform:uppercase;letter-spacing:.05em;flex-shrink:0;background:${sevBg};color:${sevColor}">${sevLabel}</span>
    <span style="font-size:.64rem;font-weight:700;padding:.1rem .45rem;border-radius:.25rem;text-transform:uppercase;letter-spacing:.06em;flex-shrink:0;background:var(--bg-elev-4);color:${toolColor}">${escHtml(toolName)}</span>
    <span style="font-family:monospace;font-size:.7rem;color:var(--text3);background:var(--bg-elev-4);padding:.1rem .45rem;border-radius:.25rem;white-space:nowrap;flex-shrink:0">${aIcon} ${escHtml(assetShort)}</span>
    <span style="font-weight:600;font-size:.83rem;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text)">${escHtml(title)}</span>
    ${analyzeBtn}
    <span style="opacity:.35;font-size:.75rem;flex-shrink:0;color:var(--text)">▾</span>
  </div>
  <div id="${uid}" style="display:none;padding:.6rem .9rem .75rem;border-top:1px solid var(--ghost);font-size:.82rem">
    <div style="white-space:pre-wrap;color:var(--text2);opacity:.8;line-height:1.55;margin-bottom:.5rem">${escHtml(item)}</div>
    ${rec ? `<div style="font-size:.79rem;color:#15803d;background:rgba(21,128,61,.08);border-radius:.35rem;padding:.45rem .7rem">▶ ${escHtml(rec)}</div>` : ''}
  </div>
</div>`;
    });
  });
  return html;
}

// ── Parallel panel: pipeline-style findings view ─────────────────────────────

let _parallelFindings = [];
let _pfFilter   = 'all';
let _pfCurView  = 'asset';

const _PF_SEV_C = { critical:'#ef4444', high:'#f97316', medium:'#eab308', info:'#60a5fa' };
const _PF_SEV_L = { critical:'CRÍTICO',  high:'ALTO',    medium:'MEDIO',   info:'INFO' };
const _PF_SEV_B = { critical:'rgba(239,68,68,.1)', high:'rgba(249,115,22,.1)', medium:'rgba(234,179,8,.1)', info:'rgba(96,165,250,.1)' };
const _PF_SEV_O = { critical:0, high:1, medium:2, info:3 };
const _PF_A_ICO = { domain:'🌐', ip:'🖥️', email:'📧', username:'👤' };

function _pfAssetType(s) {
  if (/^\d+\.\d+\.\d+\.\d+/.test(s)) return 'ip';
  if (s.includes('@')) return 'email';
  return 'domain';
}

function _groupsToFindings(groups, toolName, target) {
  const findings = [];
  groups.forEach(group => {
    const sev    = _GRP_SEV[group.type] || 'info';
    const isPort = group.type === 'port-open' || group.type === 'port-filtered';
    group.items.forEach(item => {
      findings.push({
        severity: sev, tool: toolName,
        asset: isPort ? (target || toolName) : item,
        title: _groupItemTitle(group.type, item),
        detail: item,
        recommendation: _groupItemRec(group.type),
      });
    });
  });
  return findings;
}

function _makePFC(f) {
  const color      = _PF_SEV_C[f.severity] || '#94a3b8';
  const tc         = (TOOL_COLORS[f.tool] || {}).color || '#9A6055';
  const uid        = 'pfc_' + Math.random().toString(36).slice(2);
  const aShort     = f.asset.length > 30 ? f.asset.slice(0,28)+'…' : f.asset;
  const aIcon      = _PF_A_ICO[_pfAssetType(f.asset)] || '▶';
  const isKev      = f.title.includes('[KEV]');
  const cvss       = typeof _cvssInfo === 'function' ? _cvssInfo(f.title) : null;
  const csf        = typeof _csfTag   === 'function' ? _csfTag(f) : 'ID';
  const csfStyle   = typeof CSF_STYLE !== 'undefined' ? (CSF_STYLE[csf] || CSF_STYLE.ID) : '';
  const csfLbl     = typeof CSF_LABEL !== 'undefined' ? (CSF_LABEL[csf] || csf) : csf;
  const [imp, impLbl] = typeof _sevImportance === 'function' ? _sevImportance(f.severity) : [{critical:5,high:4,medium:3,info:1}[f.severity]||1, {critical:'Crítica',high:'Alta',medium:'Media',info:'Baja'}[f.severity]||'Baja'];

  const impBar = `<div style="display:inline-flex;align-items:center;gap:.3rem;flex-shrink:0">
    <span style="font-size:.6rem;color:#94a3b8;white-space:nowrap">Importancia ${imp} - ${impLbl}</span>
    <div style="display:flex;gap:2px;align-items:center">${Array.from({length:5},(_,i)=>
      `<span style="display:inline-block;width:10px;height:5px;border-radius:1px;background:${i<imp?color:'rgba(255,255,255,.1)'}"></span>`
    ).join('')}</div></div>`;

  const cvssBadge = cvss ? `<span style="display:inline-flex;align-items:center;gap:.3rem;font-size:.65rem;font-weight:700;padding:.12rem .5rem;border-radius:.25rem;background:${cvss.bg};color:${cvss.color};white-space:nowrap;flex-shrink:0;border:1px solid ${cvss.color}44">CVSS ${cvss.ver} ${cvss.score} · ${cvss.lbl}</span>` : '';
  const kevBadge  = isKev ? `<span style="font-size:.63rem;font-weight:800;padding:.1rem .45rem;border-radius:.25rem;background:rgba(239,68,68,.2);color:#ef4444;border:1px solid rgba(239,68,68,.4);white-space:nowrap;flex-shrink:0">⚠ KEV</span>` : '';
  const csfBadge  = `<span style="font-size:.6rem;font-weight:700;padding:.1rem .45rem;border-radius:.25rem;${csfStyle};white-space:nowrap;flex-shrink:0;letter-spacing:.03em">${csf} · ${csfLbl}</span>`;

  return `<div class="pl-finding-card" style="border-left:3px solid ${color}">
  <div class="pl-finding-header" onclick="document.getElementById('${uid}').classList.toggle('open')">
    <span class="pl-sev-badge" style="background:${_PF_SEV_B[f.severity]};color:${color}">${_PF_SEV_L[f.severity]||f.severity}</span>
    <span class="pl-tool-badge" style="background:rgba(255,255,255,.07);color:${tc}">${escHtml(f.tool)}</span>
    <span style="font-family:monospace;font-size:.7rem;color:#94a3b8;background:rgba(255,255,255,.05);padding:.1rem .45rem;border-radius:.25rem;white-space:nowrap;flex-shrink:0" title="${escHtml(f.asset)}">${aIcon} ${escHtml(aShort)}</span>
    ${cvssBadge}${kevBadge}
    <span style="font-weight:600;font-size:.83rem;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(f.title)}</span>
    ${impBar}
    <span style="opacity:.35;font-size:.75rem;flex-shrink:0">▾</span>
  </div>
  <div class="pl-finding-body" id="${uid}">
    <div style="margin-bottom:.5rem">${csfBadge}</div>
    <div class="pl-finding-detail">${escHtml(f.detail)}</div>
    ${f.recommendation?`<div class="pl-finding-rec">▶ ${escHtml(f.recommendation)}</div>`:''}
  </div>
</div>`;
}

function _pfFiltered() {
  const q = ($('pf-search')?.value||'').toLowerCase();
  return _parallelFindings.filter(f =>
    (_pfFilter==='all' || f.severity===_pfFilter) &&
    (!q || f.title.toLowerCase().includes(q) || f.asset.toLowerCase().includes(q))
  );
}

window._pfSetFilter = function(sev, btn) {
  _pfFilter = sev;
  document.querySelectorAll('#parallel-summary .pl-filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  _pfRebuildViews();
};
window._pfSwitchView = function(view) {
  _pfCurView = view;
  const a=$('pf-asset'), s=$('pf-sev');
  if (a) a.style.display = view==='asset'    ? 'block':'none';
  if (s) s.style.display = view==='severity' ? 'block':'none';
  const ta=$('pf-tab-asset'), ts=$('pf-tab-sev');
  if (ta) ta.classList.toggle('active', view==='asset');
  if (ts) ts.classList.toggle('active', view==='severity');
};
window._pfRebuild = function() { _pfRebuildViews(); };

function _pfRebuildViews() {
  const filtered = _pfFiltered();
  const countEl  = $('pf-count');
  if (countEl) countEl.textContent = filtered.length===_parallelFindings.length
    ? `${_parallelFindings.length} hallazgos`
    : `${filtered.length} de ${_parallelFindings.length}`;

  const assetEl = $('pf-asset');
  if (assetEl) {
    if (!filtered.length) {
      assetEl.innerHTML = '<p class="ps-empty" style="padding:1rem 0">Sin hallazgos para el filtro.</p>';
    } else {
      const byAsset = {};
      filtered.forEach(f => (byAsset[f.asset]=byAsset[f.asset]||[]).push(f));
      const sorted = Object.entries(byAsset).sort(([,a],[,b]) => {
        const wo = arr => Math.min(...arr.map(f => _PF_SEV_O[f.severity]??99));
        return wo(a) - wo(b);
      });
      assetEl.innerHTML = sorted.map(([asset, items]) => {
        items.sort((a,b) => (_PF_SEV_O[a.severity]??99)-(_PF_SEV_O[b.severity]??99));
        const icon  = _PF_A_ICO[_pfAssetType(asset)] || '▶';
        const crit  = items.filter(f=>f.severity==='critical').length;
        const high  = items.filter(f=>f.severity==='high').length;
        const uid   = 'pag_'+Math.random().toString(36).slice(2);
        const badges = [
          crit?`<span class="pl-sev-badge" style="background:${_PF_SEV_B.critical};color:${_PF_SEV_C.critical}">${crit} CRÍTICO</span>`:'',
          high?`<span class="pl-sev-badge" style="background:${_PF_SEV_B.high};color:${_PF_SEV_C.high}">${high} ALTO</span>`:'',
        ].filter(Boolean).join('');
        return `<div class="pl-asset-group">
          <div class="pl-asset-group-header" onclick="const b=document.getElementById('${uid}');b.style.display=b.style.display==='none'?'flex':'none'">
            <span style="font-size:1rem">${icon}</span>
            <span style="font-weight:700;font-size:.88rem;flex:1;font-family:monospace">${escHtml(asset)}</span>
            ${badges}
            <span style="opacity:.35;font-size:.75rem;margin-left:.25rem">${items.length} hallazgo${items.length!==1?'s':''}</span>
            <span style="opacity:.3;font-size:.75rem">▾</span>
          </div>
          <div class="pl-asset-group-body" id="${uid}">${items.map(_makePFC).join('')}</div>
        </div>`;
      }).join('');
    }
  }

  const sevEl = $('pf-sev');
  if (sevEl) {
    sevEl.innerHTML = ['critical','high','medium','info'].map(sev => {
      const items = filtered.filter(f=>f.severity===sev).sort((a,b)=>a.asset.localeCompare(b.asset));
      if (!items.length) return '';
      const c = _PF_SEV_C[sev];
      return `<div class="pl-sev-section">
        <div class="pl-sev-section-header" style="background:${_PF_SEV_B[sev]||'rgba(255,255,255,.04)'};color:${c}">
          <span style="font-weight:800">${_PF_SEV_L[sev]}</span><span style="opacity:.6;font-size:.75rem;font-weight:400">${items.length} hallazgo${items.length!==1?'s':''}</span>
        </div>${items.map(_makePFC).join('')}
      </div>`;
    }).join('');
  }
}

function _renderParallelSummary() {
  const container = $('parallel-summary');
  if (!container) return;

  const entries = Object.entries(_parallelState);

  // Only rebuild findings from state when there is active/completed state.
  // When loading a saved analysis (empty state, findings pre-loaded), keep them as-is.
  if (entries.length) {
    _parallelFindings = [];
    entries.forEach(([,state]) => {
      if (!state.done || state._isIPScan) return;
      _parallelFindings.push(..._groupsToFindings(_parallelGroups(state), state.tool, state.target));
    });
    _parallelFindings.push(..._ipFindings);
  }

  if (!entries.length && !_parallelFindings.length) { container.innerHTML = ''; return; }

  // Status chips (running + done tools) — only when there is active state
  const chipsHtml = entries.length ? (() => {
    const chips = entries.map(([,s]) => {
      const c = TOOL_COLORS[s.tool] || {};
      const dot = s.done
        ? `<span style="color:#16a34a;font-weight:700">✓</span>`
        : `<span class="ps-spinner" style="display:inline-block;width:8px;height:8px;margin-right:2px"></span>`;
      const time = s.done ? _fmtSecs(s.elapsed) : `${s.lines}l`;
      return `<span style="display:inline-flex;align-items:center;gap:.3rem;font-size:.67rem;font-weight:600;padding:.15rem .55rem;border-radius:999px;border:1px solid ${s.done?'rgba(22,163,74,.25)':'rgba(234,179,8,.3)'};background:${s.done?'rgba(22,163,74,.06)':'rgba(234,179,8,.06)'}">
        ${dot} <span style="color:${c.color||'var(--text)'}">${escHtml(s.name)}</span><span style="opacity:.45">· ${time}</span>
      </span>`;
    }).join('');
    return `<div id="pf-chips" style="display:flex;gap:.35rem;flex-wrap:wrap;margin-bottom:.9rem">${chips}</div>`;
  })() : '';

  if (!_parallelFindings.length) {
    container.innerHTML = `${chipsHtml}
      <div style="display:flex;align-items:center;gap:.5rem;padding:.75rem 0;opacity:.55;font-size:.85rem">
        <span class="ps-spinner" style="display:inline-block"></span> Ejecutando…
      </div>`;
    return;
  }

  // Preserve search value across rebuilds
  const prevSearch = $('pf-search')?.value || '';

  // Build filter bar
  const counts = {all:_parallelFindings.length};
  _parallelFindings.forEach(f => { counts[f.severity]=(counts[f.severity]||0)+1; });
  const filterBtns = ['all','critical','high','medium','info'].map(sev => {
    const lbl = sev==='all'?'Todos':sev==='critical'?'🔴 Crítico':sev==='high'?'🟠 Alto':sev==='medium'?'🟡 Medio':'🔵 Info';
    const cnt = sev==='all'?'':counts[sev]?`<span style="opacity:.5;margin-left:3px">${counts[sev]}</span>`:'';
    return `<button class="pl-filter-btn${_pfFilter===sev?' active':''}" data-sev="${sev}"
      onclick="_pfSetFilter('${sev}',this)" style="font-size:.72rem;padding:.2rem .6rem;border-color:rgba(0,0,0,.12);color:var(--text)">${lbl}${cnt}</button>`;
  }).join('');

  container.innerHTML = `
    ${chipsHtml}
    <div style="display:flex;gap:.4rem;flex-wrap:wrap;margin-bottom:.75rem;align-items:center">
      <div style="display:flex;gap:.3rem;flex-wrap:wrap;flex:1">${filterBtns}</div>
      <input id="pf-search" placeholder="Buscar en hallazgos..." oninput="_pfRebuild()"
        style="padding:.3rem .7rem;border-radius:.4rem;border:1px solid rgba(0,0,0,.12);background:transparent;font-size:.8rem;width:180px;outline:none;color:var(--text)" value="${escHtml(prevSearch)}">
      <span id="pf-count" style="font-size:.75rem;opacity:.45;white-space:nowrap"></span>
    </div>
    <div style="display:flex;gap:.4rem;margin-bottom:.9rem;align-items:center">
      <button id="pf-tab-asset" class="pl-view-tab${_pfCurView==='asset'?' active':''}"    onclick="_pfSwitchView('asset')"    style="font-size:.78rem;border-color:rgba(0,0,0,.12)">📦 Por activo</button>
      <button id="pf-tab-sev"   class="pl-view-tab${_pfCurView==='severity'?' active':''}" onclick="_pfSwitchView('severity')" style="font-size:.78rem;border-color:rgba(0,0,0,.12)">🔴 Por severidad</button>
      ${_lastManualAnalysisId ? `<button class="secondary-btn" style="margin-left:auto;font-size:.78rem;padding:.3rem .85rem;display:inline-flex;align-items:center;gap:.4rem" onclick="window.location.href='/api/manual_analyses/${_lastManualAnalysisId}/export/pdf'">⬇ Exportar PDF</button>` : ''}
    </div>
    <div id="pf-asset" style="display:${_pfCurView==='asset'?'block':'none'}"></div>
    <div id="pf-sev"   style="display:${_pfCurView==='severity'?'block':'none'}"></div>`;

  _pfRebuildViews();
}

function _saveParallelRun(tool, subtool, state) {
  try {
    const meta    = toolMeta[tool] || {};
    const rawText = (state.allLines || []).join('\n');
    const entry = {
      tool,
      toolTitle:     meta.title || tool,
      subtoolName:   subtool.name,
      cmd:           state.cmd || '',
      target:        target || '',
      timestamp:     new Date().toLocaleTimeString('es-ES'),
      elapsed:       _fmtSecs(state.elapsed || 0),
      rawText,
      parsedItems:   parseOutput(tool, state.allLines || []),
      structuredData: state.structured || null,
      hadError:      state.hadError || false,
    };
    const arr = JSON.parse(sessionStorage.getItem('aletheia_parallel_runs') || '[]');
    arr.push(entry);
    sessionStorage.setItem('aletheia_parallel_runs', JSON.stringify(arr));
  } catch(_) {}
}

function _isPrivateIP(ip) {
  return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)/.test(ip);
}

function _extractIPsFromOutput(tool, lines) {
  const groups = parseOutput(tool, lines);
  const ips = [];
  groups.filter(g => g.type === 'ip').forEach(g => {
    g.items.forEach(item => {
      const m = item.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
      if (m) ips.push(m[1]);
    });
  });
  return [...new Set(ips)].filter(ip => !_isPrivateIP(ip));
}

function _calcManualScore(findings) {
  const c = findings.filter(f => f.severity === 'critical').length;
  const h = findings.filter(f => f.severity === 'high').length;
  const m = findings.filter(f => f.severity === 'medium').length;
  const i = findings.filter(f => f.severity === 'info').length;
  let pts = Math.min(c * 25, 50);
  pts += Math.min(h * 10, 30);
  pts += Math.min(m * 3, 15);
  pts += Math.min(i * 1, 5);
  return Math.min(100, pts);
}

function _checkParallelAllDone() {
  if (_parallelDone < _parallelTotal || _ipAnalysisPending > 0) return;
  _stopParallelTimer();
  _notifyParallelDone();
  const ipMsg = _ipFindings.length ? ` · ${_ipFindings.length} hallazgos de IPs` : '';
  showToast(`Modo paralelo completado — ${_parallelTotal} herramienta${_parallelTotal === 1 ? '' : 's'} finalizadas${ipMsg}`, 'success', 5000);
  const btn = $('launch-parallel-btn');
  if (btn) btn.disabled = false;

  // Persist to database
  const manualTargets = [...new Set(
    Object.values(_parallelState)
      .filter(s => !s._isIPScan && s.target)
      .map(s => s.target)
  )];
  const manualTools = [...new Set(
    Object.values(_parallelState)
      .filter(s => !s._isIPScan && s.tool)
      .map(s => s.tool)
  )];
  const manualScore = _calcManualScore(_parallelFindings);
  fetch('/api/manual_analyses/save', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      targets:  manualTargets,
      tools:    manualTools,
      findings: _parallelFindings,
      score:    manualScore,
    }),
  })
  .then(r => r.json())
  .then(d => {
    if (d.ok) {
      _lastManualAnalysisId = d.id;
      showToast('💾 Análisis guardado', 'success', 3000);
      _renderParallelSummary();
      if (typeof loadManualHistory === 'function') loadManualHistory();
    }
  })
  .catch(() => {});
}

function _analyzeIPFromManual(ip) {
  _queuedIPs.add(ip);
  _ipAnalysisPending++;
  const key      = `_ip_${ip.replace(/\./g, '_')}`;
  const ipColor  = { color: '#fb923c', bg: 'rgba(251,146,60,.08)' };

  _parallelState[key] = {
    _isIPScan: true,
    tool: 'nmap',
    name: `IP: ${ip}`,
    target: ip,
    startTime: Date.now(),
    done: false,
    lines: 0,
    elapsed: 0,
    hadError: false,
  };
  _renderParallelSummary();
  appendParallelLine('nmap', `▶ IP descubierta — iniciando análisis completo de ${ip}`, ipColor, true);

  fetch('/api/pipeline/run_tool', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tool: 'full_ip', target: ip }),
  })
  .then(r => r.json())
  .then(({ pipeline_id, error }) => {
    if (error) {
      appendParallelLine('nmap', `✖ Error al analizar ${ip}: ${error}`, ipColor, false);
      _parallelState[key].done = true;
      _parallelState[key].hadError = true;
      _ipAnalysisPending--;
      _renderParallelSummary();
      _checkParallelAllDone();
      return;
    }
    const es = new EventSource(`/api/pipeline/stream/${pipeline_id}`);
    es.onmessage = ev => {
      const d = JSON.parse(ev.data);
      if (d.type === 'stage') {
        _parallelState[key].lines++;
        appendParallelLine('nmap', d.msg, ipColor, false);
      } else if (d.type === 'error') {
        appendParallelLine('nmap', `✖ ${d.msg}`, ipColor, false);
      } else if (d.type === 'finding') {
        _ipFindings.push(d);
        _renderParallelSummary();
      } else if (d.type === 'pipeline_complete') {
        es.close();
        _parallelState[key].done = true;
        _parallelState[key].elapsed = Math.floor((Date.now() - _parallelState[key].startTime) / 1000);
        _ipAnalysisPending--;
        appendParallelLine('nmap', `✓ ${ip} — análisis completo · score ${d.score ?? 0}/100`, ipColor, true);
        _renderParallelSummary();
        _checkParallelAllDone();
      }
    };
    es.onerror = () => {
      es.close();
      _parallelState[key].done = true;
      _parallelState[key].hadError = true;
      _ipAnalysisPending--;
      _renderParallelSummary();
      _checkParallelAllDone();
    };
  })
  .catch(err => {
    appendParallelLine('nmap', `✖ Error: ${err}`, ipColor, false);
    _parallelState[key].done = true;
    _parallelState[key].hadError = true;
    _ipAnalysisPending--;
    _renderParallelSummary();
    _checkParallelAllDone();
  });
}

function launchParallel() {
  const checked = [...document.querySelectorAll('#parallel-subtool-grid .pg-checkbox:checked')];
  if (!checked.length) return;

  // Build target list: all scope domains + IPs, or fallback to current target
  const scope = getScope();
  const scopeTargets = [
    ...(scope?.domains  || []),
    ...(scope?.ipRanges || []),
  ].filter(Boolean);
  const targets = scopeTargets.length ? scopeTargets : (target ? [target] : []);

  if (!targets.length) {
    const parallelOut = $('parallel-out');
    if (parallelOut) parallelOut.innerHTML =
      `<div style="color:var(--red);padding:20px;font-size:.85rem">⚠ Define el alcance o establece un objetivo antes de lanzar.</div>`;
    return;
  }

  // Target type helpers
  const _isIPRange = t => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d+)?$/.test(t);
  const _isEmail   = t => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(t);
  const _isDomain  = t => !_isIPRange(t) && !_isEmail(t);

  // Each checkbox × each compatible target = one job
  // Deduplicate: same command string must never appear twice regardless of cause
  const seenCmds = new Set();
  const jobs = [];
  checked.forEach(checkbox => {
    const tool = checkbox.dataset.tool;
    const idx  = parseInt(checkbox.dataset.idx);
    const subtool = (SUBTOOLS[tool] || [])[idx];
    const inputType = subtool?.inputType || 'any';

    const seenEffective = new Set();
    targets.forEach(tgt => {
      if (inputType === 'domain' && !_isDomain(tgt)) return;
      if (inputType === 'email'  && !_isEmail(tgt))  return;
      const effectiveTgt = subtool.apexOnly ? _apexDomain(tgt) : tgt;
      if (seenEffective.has(effectiveTgt)) return;
      seenEffective.add(effectiveTgt);
      const dedupeKey = `${tool}::${idx}::${effectiveTgt}`;
      if (seenCmds.has(dedupeKey)) return;
      seenCmds.add(dedupeKey);
      jobs.push({ checkbox, tgt: effectiveTgt });
    });
  });

  Object.keys(_parallelState).forEach(k => delete _parallelState[k]);
  _parallelRequestIds.clear();
  _parallelControllers.clear();
  _parallelTotal     = jobs.length;
  _parallelDone         = 0;
  _queuedIPs            = new Set();
  _ipAnalysisPending    = 0;
  _ipFindings           = [];
  _lastManualAnalysisId = null;
  // Pre-seed queuedIPs with explicit IP targets to avoid re-analyzing them
  targets.forEach(t => { if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(t)) _queuedIPs.add(t); });

  // Clear previous parallel run history for this session
  try { sessionStorage.setItem('aletheia_parallel_runs', '[]'); } catch(_) {}

  const parallelOut = $('parallel-out');
  if (parallelOut) parallelOut.innerHTML = '';

  const summary = $('parallel-summary');
  if (summary) summary.innerHTML = '';

  const launchBtn = $('launch-parallel-btn');
  if (launchBtn) launchBtn.disabled = true;

  if (Notification.permission === 'default') Notification.requestPermission();

  _startParallelTimer();

  jobs.forEach(({ checkbox, tgt }) => {
    const tool = checkbox.dataset.tool;
    const idx  = parseInt(checkbox.dataset.idx, 10);
    // Use tgt+tool+idx as unique key when multiple targets
    const key  = targets.length > 1 ? `${tgt}__${tool}__${idx}` : _parallelKey(tool, idx);
    const subtool = SUBTOOLS[tool][idx];
    const cmd  = subtool.cmd(tgt);
    const color = TOOL_COLORS[tool];

    if (cmd.includes('OBJETIVO')) {
      appendParallelLine(tool, `[ERROR] ${UI_TEXT.missingTarget}`, color, false);
      _parallelTotal--;
      return;
    }

    _parallelState[key] = {
      tool,
      idx,
      name: targets.length > 1 ? `${subtool.name} [${tgt}]` : subtool.name,
      cmd,
      target: tgt,
      startTime: Date.now(),
      done: false,
      lines: 0,
      structured: null,
      elapsed: 0,
      hadError: false
    };
    _renderParallelSummary();

    const requestId = crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random());
    _parallelRequestIds.add(requestId);
    _setParallelStopBtn(true);
    const allLines = [];

    const _ctrl = streamCmd(
      cmd,
      requestId,
      (msg) => {
        if (msg.type === 'heartbeat') return;
        if (msg.type === 'start') {
          appendParallelLine(tool, `▶ ${subtool.name}: ${cmd}`, color, true);
        } else if (msg.type === 'line') {
          _parallelState[key].lines++;
          appendParallelLine(tool, msg.stream === 'stderr' ? `⚠ ${msg.message}` : msg.message, color, false);
          allLines.push(msg.message);
        } else if (msg.type === 'structured') {
          _parallelState[key].structured = msg.data;
        } else if (msg.type === 'exit') {
          _parallelState[key].hadError = true;
          appendParallelLine(tool, `✖ Exit code: ${msg.message}`, color, false);
        } else if (msg.type === 'error') {
          _parallelState[key].hadError = true;
          appendParallelLine(tool, `✖ ${msg.message}`, color, false);
        } else if (msg.type === 'done') {
          _parallelState[key].done = true;
          _parallelState[key].elapsed = Math.floor((Date.now() - _parallelState[key].startTime) / 1000);
          _parallelState[key].allLines = allLines;
          _parallelDone++;
          _parallelRequestIds.delete(requestId);
          _parallelControllers.delete(requestId);
          if (_parallelRequestIds.size === 0) _setParallelStopBtn(false);

          // Analyze any new public IPs — use _parallelGroups (same source as findings, handles structured + raw)
          _parallelGroups(_parallelState[key])
            .filter(g => g.type === 'ip')
            .flatMap(g => g.items.map(item => { const m = item.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/); return m ? m[1] : null; }))
            .filter((ip, i, a) => ip && !_isPrivateIP(ip) && a.indexOf(ip) === i)
            .forEach(ip => { if (!_queuedIPs.has(ip)) _analyzeIPFromManual(ip); });

          // Persist to sessionStorage for report generation
          _saveParallelRun(tool, subtool, _parallelState[key]);

          if (_parallelState[key].hadError) {
            appendParallelLine(tool, `✖ ${subtool.name} finalizó con error en ${_fmtSecs(_parallelState[key].elapsed)}`, color, true);
          } else {
            appendParallelLine(tool, `✓ ${subtool.name} completado en ${_fmtSecs(_parallelState[key].elapsed)}`, color, true);
          }

          _renderParallelSummary();
          _checkParallelAllDone();
        }
      },
      (err) => {
        _parallelState[key].done = true;
        _parallelState[key].hadError = true;
        _parallelState[key].elapsed = Math.floor((Date.now() - _parallelState[key].startTime) / 1000);
        _parallelState[key].allLines = allLines;
        _parallelDone++;
        _parallelRequestIds.delete(requestId);
        _parallelControllers.delete(requestId);
        if (_parallelRequestIds.size === 0) _setParallelStopBtn(false);

        _saveParallelRun(tool, subtool, _parallelState[key]);
        appendParallelLine(tool, `[ERROR] ${err}`, color, false);
        _renderParallelSummary();
        _checkParallelAllDone();
      }
    );
    _parallelControllers.set(requestId, _ctrl);
  });
}

function _setParallelStopBtn(visible) {
  const btn = document.getElementById('parallel-stop-btn');
  if (btn) btn.style.display = visible ? 'inline-flex' : 'none';
}

async function stopParallelAnalysis() {
  const btn = document.getElementById('parallel-stop-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Parando...'; }

  const ids = [..._parallelRequestIds];
  _parallelRequestIds.clear();

  // Abort frontend SSE streams immediately
  ids.forEach(id => {
    const ctrl = _parallelControllers.get(id);
    if (ctrl) { try { ctrl.abort(); } catch (_) {} }
    _parallelControllers.delete(id);
  });

  // Also kill backend subprocesses
  await Promise.allSettled(ids.map(id =>
    fetch('/stop', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ request_id: id }),
    })
  ));

  _stopParallelTimer();
  _setParallelStopBtn(false);
  const launchBtn = document.getElementById('launch-parallel-btn');
  if (launchBtn) launchBtn.disabled = false;

  // Marcar como terminados los procesos aún en vuelo
  Object.keys(_parallelState).forEach(k => {
    if (!_parallelState[k].done) {
      _parallelState[k].done = true;
      _parallelState[k].hadError = true;
      _parallelDone++;
    }
  });
  _renderParallelSummary();
  if (typeof showToast === 'function') showToast('Análisis detenido', 'warning', 3000);
}

function switchParallelTab(tab, btn) {
  ['summary', 'raw'].forEach(t => {
    const el = $(`ptab-${t}`);
    if (el) el.style.display = t === tab ? 'block' : 'none';
  });
  document.querySelectorAll('#panel-parallel .out-tab').forEach(el => el.classList.remove('active'));
  if (btn) btn.classList.add('active');
}

function appendParallelLine(tool, message, color, isHeader = false) {
  const output = $('parallel-out');
  if (!output) return;

  // Remove empty-state placeholder on first real line
  const placeholder = output.querySelector('.parallel-empty-terminal');
  if (placeholder) placeholder.remove();

  // Color-code by message type
  let msgColor;
  if (/^✖|^\[ERROR\]/.test(message))       msgColor = '#f87171'; // red — error
  else if (/^⚠/.test(message))             msgColor = '#fbbf24'; // yellow — warning
  else if (/^✓/.test(message))             msgColor = '#4ade80'; // green — success
  else if (/^▶/.test(message))             msgColor = '#93c5fd'; // blue — command header
  else                                      msgColor = '#c9d8ed'; // default terminal

  const line = document.createElement('div');
  line.className = 'pline';
  line.innerHTML = `<span class="ptag" style="color:${color.color}">[${tool}]</span> <span class="ptext ${isHeader ? 'ptext-strong' : ''}" style="color:${msgColor}">${escHtml(message)}</span>`;

  output.appendChild(line);
  output.scrollTop = output.scrollHeight;
}

function clearParallel() {
  document.querySelectorAll('#parallel-subtool-grid .pg-checkbox').forEach(cb => {
    cb.checked = false;
    const card = cb.closest('.pg-card');
    if (card) card.classList.remove('pg-selected');
  });
  document.querySelectorAll('.pg-select-all').forEach(btn => { btn.textContent = 'Seleccionar todo'; });
  // Reset parallel state
  Object.keys(_parallelState).forEach(k => delete _parallelState[k]);
  _parallelFindings = [];
  _pfFilter   = 'all';
  _pfCurView  = 'asset';
  _parallelTotal     = 0;
  _parallelDone      = 0;
  _queuedIPs            = new Set();
  _ipAnalysisPending    = 0;
  _ipFindings           = [];
  _lastManualAnalysisId = null;
  _stopParallelTimer();
  updateParallelCount();
  setHtml('parallel-summary', `
  <div class="parallel-empty-state">
    <div class="parallel-empty-icon">⚡</div>
    <div class="parallel-empty-title">Sin ejecución activa</div>
    <div class="parallel-empty-text">
      Selecciona varias subherramientas y pulsa Lanzar para ver el resumen unificado.
    </div>
  </div>
`);
  setHtml('parallel-out', `
  <div class="parallel-empty-terminal">
    <span class="empty-output-text">$ _</span>
  </div>
`);
  // Reset tabs: show Resumen, hide terminal
  const tabSummary = $('ptab-summary');
  const tabRaw     = $('ptab-raw');
  if (tabSummary) tabSummary.style.display = 'block';
  if (tabRaw)     tabRaw.style.display     = 'none';
  document.querySelectorAll('#panel-parallel .out-tab').forEach((b, i) => b.classList.toggle('active', i === 0));
}

/* ── Scope management ────────────────────────────────────────────────────── */

const SCOPE_KEY = 'aletheia_scope';

function getScope() {
  try { return JSON.parse(localStorage.getItem(SCOPE_KEY) || 'null'); } catch(_) { return null; }
}

function saveScope() {
  const scanEl = document.querySelector('input[name="scope-scan"]:checked');
  const scope = {
    caseName:    ($('scope-case')    || {}).value?.trim() || '',
    org_id:      ($('scope-org') || {}).value || '',
    client:      ($('scope-org') ? ($('scope-org').options[$('scope-org').selectedIndex] || {}).text || '' : ''),
    responsable: ($('scope-resp')    || {}).value?.trim() || '',
    domains:     ($('scope-domains') || {}).value?.split(',').map(d => d.trim()).filter(Boolean) || [],
    ipRanges:    ($('scope-ips')     || {}).value?.split(',').map(ip => ip.trim()).filter(Boolean) || [],
    scanType:    scanEl ? scanEl.value : 'active',
    expiry:      ($('scope-expiry')  || {}).value || '',
    savedAt:     new Date().toISOString(),
  };
  localStorage.setItem(SCOPE_KEY, JSON.stringify(scope));
  renderScopeStatus();

  // Auto-set topbar target to the first approved domain so tools run against the right objective
  if (scope.domains.length > 0) {
    const firstDomain = scope.domains[0];
    const inp = document.getElementById('targetInput');
    if (inp) { inp.value = firstDomain; updateTarget(firstDomain); }
  }

  const msg = $('scope-saved-msg');
  if (msg) { msg.style.display = 'block'; setTimeout(() => { msg.style.display = 'none'; }, 2500); }
}

let _discoverScanId  = null;
let _discoverPollTimer = null;

async function discoverHosts() {
  const ipsEl    = $('scope-ips');
  const btn      = $('discover-hosts-btn');
  const stopBtn  = $('discover-stop-btn');
  const resultEl = $('discover-hosts-result');

  const ranges = (ipsEl?.value || '').split(',').map(r => r.trim()).filter(Boolean);
  if (!ranges.length) {
    resultEl.innerHTML = `<span style="color:var(--red);font-size:.82rem">⚠ Añade al menos un rango CIDR antes de escanear</span>`;
    resultEl.style.display = 'block';
    return;
  }

  btn.disabled = true;
  btn.textContent = '⏳ Escaneando...';
  stopBtn.style.display = 'inline-flex';
  resultEl.innerHTML = '';
  resultEl.style.display = 'none';

  try {
    const resp = await fetch('/api/nmap/discover', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ranges })
    });
    const data = await resp.json();
    if (data.error) {
      _discoverFinish();
      resultEl.innerHTML = `<span style="color:var(--red);font-size:.82rem">⚠ ${data.error}</span>`;
      return;
    }
    _discoverScanId = data.scan_id;
    _discoverPoll();
  } catch(e) {
    _discoverFinish();
    resultEl.innerHTML = `<span style="color:var(--red);font-size:.82rem">⚠ Error de conexión con el servidor</span>`;
  }
}

function _discoverPoll() {
  if (!_discoverScanId) return;
  _discoverPollTimer = setTimeout(async () => {
    try {
      const resp = await fetch(`/api/nmap/status/${_discoverScanId}`);
      const data = await resp.json();
      const resultEl = $('discover-hosts-result');

      if (data.status === 'running') {
        if (resultEl) {
          const count = data.hosts?.length || 0;
          resultEl.innerHTML = `<span style="color:var(--text3);font-size:.82rem">⏳ Escaneando… ${count > 0 ? `${count} hosts encontrados hasta ahora` : ''}</span>`;
        }
        _discoverPoll();
      } else {
        _discoverFinish();
        if (data.status === 'error') {
          resultEl.innerHTML = `<span style="color:var(--red);font-size:.82rem">⚠ ${data.error}</span>`;
        } else if (data.status === 'stopped') {
          _discoverShowResults(data.hosts, true);
        } else {
          _discoverShowResults(data.hosts, false);
        }
      }
    } catch(e) {
      _discoverFinish();
      const resultEl = $('discover-hosts-result');
      if (resultEl) resultEl.innerHTML = `<span style="color:var(--red);font-size:.82rem">⚠ Error de conexión</span>`;
    }
  }, 2000);
}

function _discoverShowResults(hosts, stopped) {
  const resultEl = $('discover-hosts-result');
  if (!resultEl) return;
  if (!hosts?.length) {
    resultEl.innerHTML = `<span style="color:var(--text3);font-size:.82rem">${stopped ? 'Detenido — sin hosts encontrados' : 'Sin hosts activos en el rango'}</span>`;
    return;
  }
  const chips = hosts.map(ip =>
    `<span class="parallel-scope-chip parallel-scope-ip" style="cursor:default">${ip}</span>`
  ).join('');
  const label = stopped ? `${hosts.length} hosts encontrados (detenido)` : `${hosts.length} hosts activos encontrados`;
  resultEl.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
      <span style="font-size:.78rem;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.06em">${label}</span>
      <button class="clr-btn" onclick="clearDiscoverResults()" title="Limpiar resultados">✕ Limpiar</button>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:10px">${chips}</div>
    <button class="secondary-btn" onclick="addDiscoveredToScope(${JSON.stringify(hosts).replace(/"/g,'&quot;')})" style="font-size:.78rem">
      + Añadir todos al alcance
    </button>`;
}

function _discoverFinish() {
  const btn     = $('discover-hosts-btn');
  const stopBtn = $('discover-stop-btn');
  if (btn)     { btn.disabled = false; btn.textContent = '🔍 Descubrir hosts activos'; }
  if (stopBtn)   stopBtn.style.display = 'none';
  clearTimeout(_discoverPollTimer);
  _discoverScanId = null;
}

async function stopDiscover() {
  if (!_discoverScanId) return;
  const id = _discoverScanId;
  clearTimeout(_discoverPollTimer);
  try {
    await fetch(`/api/nmap/stop/${id}`, { method: 'POST' });
    // Poll once more to get partial results
    const resp = await fetch(`/api/nmap/status/${id}`);
    const data = await resp.json();
    _discoverFinish();
    _discoverShowResults(data.hosts, true);
  } catch(e) {
    _discoverFinish();
  }
}

function clearDiscoverResults() {
  const resultEl = $('discover-hosts-result');
  if (resultEl) { resultEl.innerHTML = ''; resultEl.style.display = 'none'; }
}

function addDiscoveredToScope(hosts) {
  const ipsEl = $('scope-ips');
  if (!ipsEl) return;
  const existing = ipsEl.value.split(',').map(r => r.trim()).filter(Boolean);
  const toAdd = hosts.filter(h => !existing.includes(h));
  ipsEl.value = [...existing, ...toAdd].join(', ');
  saveScope();
  const resultEl = $('discover-hosts-result');
  if (resultEl) {
    const addBtn = resultEl.querySelector('button');
    if (addBtn) { addBtn.textContent = `✅ ${toAdd.length} IPs añadidas al alcance`; addBtn.disabled = true; }
  }
}

function clearScope() {
  localStorage.removeItem(SCOPE_KEY);
  ['scope-case','scope-resp','scope-domains','scope-ips','scope-expiry'].forEach(id => {
    const el = $(id); if (el) el.value = '';
  });
  const orgSel = $('scope-org'); if (orgSel) orgSel.value = '';
  const scanEl = document.querySelector('input[name="scope-scan"][value="active"]');
  if (scanEl) scanEl.checked = true;
  renderScopeStatus();
}

function renderScopeStatus() {
  const scope = getScope();

  // Populate form from saved scope
  if (scope) {
    const set = (id, val) => { const el = $(id); if (el) el.value = val || ''; };
    set('scope-case',    scope.caseName);
    const orgSel = $('scope-org');
    if (orgSel && scope.org_id) orgSel.value = scope.org_id;
    set('scope-resp',    scope.responsable);
    set('scope-domains', (scope.domains  || []).join(', '));
    set('scope-ips',     (scope.ipRanges || []).join(', '));
    set('scope-expiry',  scope.expiry);
    const scanEl = document.querySelector(`input[name="scope-scan"][value="${scope.scanType || 'active'}"]`);
    if (scanEl) scanEl.checked = true;

    // Restore topbar target to scope's first domain (only if topbar is currently empty)
    const inp = document.getElementById('targetInput');
    if (inp && !inp.value.trim() && scope.domains?.length > 0) {
      inp.value = scope.domains[0];
      updateTarget(scope.domains[0]);
    }
  }

  // Active scope card
  const card = $('scope-active-card');
  if (card) card.style.display = scope ? 'block' : 'none';

  if (scope && card) {
    const titleEl = $('scope-active-title');
    if (titleEl) titleEl.textContent = scope.caseName || '(sin nombre)';

    const badgesEl = $('scope-active-badges');
    if (badgesEl) {
      const expiryWarn = scope.expiry && new Date(scope.expiry) < new Date();
      const scanLabel  = scope.scanType === 'passive' ? 'Solo pasivo' : 'Activo permitido';
      const scanCls    = scope.scanType === 'passive' ? 'scope-badge-passive' : 'scope-badge-active-scan';
      badgesEl.innerHTML = `
        <span class="scope-badge scope-badge-active">ACTIVO</span>
        <span class="scope-badge ${scanCls}">${scanLabel}</span>
        ${scope.expiry ? `<span class="scope-badge ${expiryWarn ? 'scope-badge-expired' : 'scope-badge-expiry'}">
          ${expiryWarn ? '⚠ EXPIRADO' : 'Exp: ' + scope.expiry}</span>` : ''}
      `;
    }

    const bodyEl = $('scope-active-body');
    if (bodyEl) {
      // Domains and IPs as clickable target chips
      const _chip = v =>
        `<span class="scope-domain-chip" onclick="setTargetFromScope('${escHtml(v)}')" title="Establecer como objetivo activo">
          ${escHtml(v)} <span class="scope-chip-arrow">→</span>
        </span>`;
      const domainChips = (scope.domains  || []).map(_chip).join('');
      const ipChips     = (scope.ipRanges || []).map(_chip).join('');

      const fields = [
        ['Cliente',            escHtml(scope.client || '—'), false],
        ['Responsable',        escHtml(scope.responsable || '—'), false],
        ['Dominios aprobados', domainChips || '—', true],
        ['Rangos IP',          ipChips     || '—', true],
        ['Expiración',         escHtml(scope.expiry || '—'), false],
      ];
      bodyEl.innerHTML = fields.map(([k, v, raw]) => `
        <div class="scope-active-field">
          <div class="scope-active-label">${k}</div>
          <div class="scope-active-val">${raw ? v : v}</div>
        </div>`).join('');
    }
  }

  // Home panel scope card
  const homeEmpty  = $('scope-home-empty');
  const homeActive = $('scope-home-active');
  if (homeEmpty)  homeEmpty.style.display  = scope ? 'none' : 'flex';
  if (homeActive) homeActive.style.display = scope ? 'flex' : 'none';

  if (scope && homeActive) {
    const cnEl = $('scope-home-casename');
    if (cnEl) cnEl.textContent = scope.caseName || '(sin nombre)';
    const clEl = $('scope-home-client');
    if (clEl) clEl.textContent = scope.client || '';

    const chipsEl = $('scope-home-chips');
    if (chipsEl) {
      const expiryWarn = scope.expiry && new Date(scope.expiry) < new Date();
      const scanCls = scope.scanType === 'passive' ? 'scope-badge-passive' : 'scope-badge-active-scan';
      chipsEl.innerHTML = `
        <span class="scope-badge scope-badge-active">ACTIVO</span>
        <span class="scope-badge ${scanCls}">${scope.scanType === 'passive' ? 'Solo pasivo' : 'Activo permitido'}</span>
        ${scope.domains?.length ? `<span class="scope-badge scope-badge-dom">${scope.domains.length} dominio${scope.domains.length!==1?'s':''}</span>` : ''}
        ${scope.ipRanges?.length ? `<span class="scope-badge scope-badge-ip">${scope.ipRanges.length} rango${scope.ipRanges.length!==1?'s':''} IP</span>` : ''}
        ${scope.expiry ? `<span class="scope-badge ${expiryWarn ? 'scope-badge-expired' : 'scope-badge-expiry'}">${expiryWarn ? '⚠ Expirado' : 'Exp: '+scope.expiry}</span>` : ''}
      `;
    }
  }

  // Parallel panel scope chips (domains + IPs)
  const pChipsWrap = $('parallel-scope-chips');
  const pChipsList = $('parallel-scope-list');
  if (pChipsWrap && pChipsList) {
    const hasDomains = scope?.domains?.length > 0;
    const hasIPs     = scope?.ipRanges?.length > 0;
    if (scope && (hasDomains || hasIPs)) {
      pChipsList.innerHTML =
        (scope.domains  || []).map(v =>
          `<span class="parallel-scope-chip parallel-scope-dom" onclick="setTargetFromScope('${escHtml(v)}')" title="Usar como objetivo">${escHtml(v)}</span>`
        ).join('') +
        (scope.ipRanges || []).map(v =>
          `<span class="parallel-scope-chip parallel-scope-ip" onclick="setTargetFromScope('${escHtml(v)}')" title="Usar como objetivo">${escHtml(v)}</span>`
        ).join('');
      pChipsWrap.style.display = 'flex';
    } else {
      pChipsWrap.style.display = 'none';
    }
  }

  // Scope indicator (updated when target changes too)
  _updateScopeIndicator();
}

function setTargetFromScope(domain) {
  const inp = document.getElementById('targetInput');
  if (inp) inp.value = domain;
  updateTarget(domain);
}

function _updateScopeIndicator() {
  const ind = $('scope-indicator');
  if (!ind) return;
  const scope = getScope();
  if (!scope || (!scope.domains?.length && !scope.ipRanges?.length) || !target) {
    ind.style.display = 'none';
    return;
  }
  const status = _checkTargetInScope(target, scope);
  ind.style.display = 'inline-block';
  if (status === 'in') {
    ind.textContent = '✓ IN SCOPE';
    ind.className = 'scope-topbar-indicator scope-ind-in';
  } else {
    ind.textContent = '⚠ OUT OF SCOPE';
    ind.className = 'scope-topbar-indicator scope-ind-out';
  }
}

function _checkTargetInScope(tgt, scope) {
  if (!tgt) return 'unknown';
  const domainMatch = (scope.domains || []).some(d => tgt === d || tgt.endsWith('.' + d));
  if (domainMatch) return 'in';
  const ipRe = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  if (ipRe.test(tgt)) {
    const ipMatch = (scope.ipRanges || []).some(cidr => _ipInCidr(tgt, cidr));
    return ipMatch ? 'in' : 'out';
  }
  return 'out';
}

function _ipInCidr(ip, cidr) {
  try {
    const [base, bits] = cidr.split('/');
    const mask = bits ? ~((1 << (32 - parseInt(bits))) - 1) : -1;
    const ipInt   = ip.split('.').reduce((a, o) => (a << 8) | parseInt(o), 0) >>> 0;
    const baseInt = base.split('.').reduce((a, o) => (a << 8) | parseInt(o), 0) >>> 0;
    return (ipInt & mask) === (baseInt & mask);
  } catch(_) { return false; }
}

/* ── Plan step runner (kept for compatibility with hidden HTML refs) ──────── */
function goToPlan(tool, idx) { show(tool, null); }
function runPlanStep(cmdTemplate, tool) {
  // Plan panel removed — stub kept for hidden HTML references
  show(tool, null);
  const rawOutput = $(`raw-out-${tool}`);
  const cmdInput = $(`cmd-${tool}`);
  const cmdBox = $(`tb-${tool}`);
  const cmd = cmdTemplate.replace(/OBJETIVO/g, target || 'OBJETIVO');
  if (cmd.includes('OBJETIVO')) {
    setHtml(`results-${tool}`, makeInfoText(UI_TEXT.missingTarget, 'error'));
    return;
  }
  if (rawOutput) rawOutput.innerHTML = '';
  if (cmdInput) cmdInput.value = cmd;
  if (cmdBox) cmdBox.style.display = 'block';

  const writer = createBufferedWriter(rawOutput);

  setStatus(tool, 'running');
  if ($(`run-${tool}`)) $(`run-${tool}`).disabled = true;
  if ($(`stop-${tool}`)) $(`stop-${tool}`).style.display = 'inline-block';

  setHtml(`results-${tool}`, makeInfoText(UI_TEXT.runningFromPlan));

  const allLines = [];
  let hadError = false;

  const requestId = crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random());
  runningRequests[tool] = requestId;

  streamCmd(
    cmd,
    requestId,
    (msg) => {

      if (msg.type === 'heartbeat') return;

      if (msg.type === 'start') {
        writer.write(`▶ ${msg.message}\n`);
        return;
      }

      if (msg.type === 'line') {
        if (msg.stream === 'stdout') {
          allLines.push(msg.message);
        }
        writer.write(`${msg.stream === 'stderr' ? '⚠ ' : ''}${msg.message}\n`);
        return;
      }

      if (msg.type === 'exit') {
        hadError = true;
        writer.write(`✖ Process finished with code ${msg.message}\n`);
        return;
      }

      if (msg.type === 'error') {
        hadError = true;
        writer.write(`✖ ${msg.message}\n`);
        return;
      }

      if (msg.type === 'structured') {
        _structuredCache[tool] = msg.data;
        return;
      }

      if (msg.type === 'done') {
        writer.flushNow();

        if (hadError) {
          if ($(`sr-${tool}`)) $(`sr-${tool}`).style.display = 'none';
          if ($(`sd-${tool}`)) $(`sd-${tool}`).style.display = 'none';

          const idle = $(`ss-${tool}`);
          if (idle) {
            idle.style.display = 'inline';
            idle.textContent = '✖ Error';
          }

          resetBtn(tool);
          delete runningRequests[tool];
          return;
        }

        setStatus(tool, 'done');

        const structured = _structuredCache[tool];
        delete _structuredCache[tool];

        if (structured && renderStructured(tool, structured)) {
          // rendered from JSON
        } else {
          const parsed = parseOutput(tool, allLines);
          if (parsed.length) renderParsed(tool, parsed);
          else setHtml(`results-${tool}`, makeInfoText(UI_TEXT.emptyStructured));
        }

        resetBtn(tool);
        delete runningRequests[tool];
      }
    },
    (err) => {
      writer.flushNow();
      setHtml(`results-${tool}`, makeInfoText(`Error de conexión: ${err}`, 'error'));
      resetBtn(tool);
      delete runningRequests[tool];
    }
  );
}

// ── Parallel scan profiles ────────────────────────────────────────────────────

const PARALLEL_PROFILES = [
  {
    id: 'inicial',
    name: 'Reconocimiento inicial',
    icon: '🔎',
    desc: 'Punto de partida pasivo: WHOIS, DNS, theHarvester, subdominios OSINT y registros DNS',
    tools: ['WHOIS', 'theHarvester', 'DNSRecon', 'dnsx — registros', 'enum -passive', 'Pasivo básico'],
  },
  {
    id: 'subdominios',
    name: 'Subdominios',
    icon: '🌐',
    desc: 'Enumeración completa de subdominios con todas las fuentes disponibles',
    tools: ['intel', 'enum -passive', 'enum -active', 'Pasivo básico', 'Todas las fuentes'],
  },
  {
    id: 'dns',
    name: 'DNS / Infraestructura',
    icon: '🌍',
    desc: 'Resolución DNS, registros, transferencias de zona y probe HTTP de hosts activos',
    tools: ['WHOIS', 'DNSRecon', 'dnsx — registros', 'intel', 'httpx — probe'],
  },
  {
    id: 'web',
    name: 'Superficie web',
    icon: '🕸',
    desc: 'Fingerprinting web, WAF, TLS, crawling y probe HTTP',
    tools: ['httpx — probe', 'WhatWeb', 'WafW00f', 'sslscan', 'FinalRecon — cabeceras + SSL', 'Estático', 'Con JS (-jc)'],
  },
  {
    id: 'urls',
    name: 'URL Discovery',
    icon: '🔗',
    desc: 'Recolección de URLs desde archivos históricos y crawling activo',
    tools: ['gau — todas las fuentes', 'waybackurls', 'Estático', 'Con JS (-jc)'],
  },
  {
    id: 'vuln',
    name: 'Vulnerabilidades',
    icon: '☢',
    desc: 'Nuclei sobre el objetivo: CVEs, misconfigs y exposures',
    tools: ['CVEs conocidos', 'Misconfigs + exposures', 'Tech detect'],
  },
  {
    id: 'red',
    name: 'Escaneo de red',
    icon: '🔌',
    desc: 'Nmap con scripts NSE, TLS y traza de red (un solo escaneo completo)',
    tools: ['Nmap + NSE', 'sslscan', 'sslyze', 'Traceroute'],
  },
  {
    id: 'identidad',
    name: 'Identidad / OSINT',
    icon: '👤',
    desc: 'Búsqueda de alias en redes sociales, plataformas y verificación de email',
    tools: ['Sherlock', 'Maigret', 'Blackbird (username)', 'usufy (OSRFramework)', 'Holehe (email)', 'Blackbird (email)'],
  },
  {
    id: 'pasivo',
    name: 'Completo pasivo',
    icon: '⚡',
    desc: 'Todo lo pasivo: sin interacción directa con el objetivo',
    tools: ['WHOIS', 'theHarvester', 'DNSRecon', 'dnsx — registros', 'intel', 'enum -passive', 'Pasivo básico', 'WhatWeb', 'sslscan', 'FinalRecon — DNS + subdominios', 'gau — todas las fuentes', 'Listar snapshots'],
  },
  {
    id: 'full',
    name: 'Análisis completo',
    icon: '🎯',
    desc: 'Todas las herramientas disponibles',
    tools: null,
  },
];

function _buildParallelProfilesBar() {
  const list = $('parallel-profiles-list');
  if (!list) return;
  list.innerHTML = PARALLEL_PROFILES.map(p =>
    `<button class="pp-btn" data-id="${p.id}" onclick="applyParallelProfile('${p.id}')" title="${escHtml(p.desc || '')}">
      ${p.icon} ${escHtml(p.name)}
    </button>`
  ).join('');
}

function applyParallelProfile(id) {
  const profile = PARALLEL_PROFILES.find(p => p.id === id);
  if (!profile) return;

  document.querySelectorAll('#parallel-subtool-grid .pg-checkbox').forEach(cb => {
    cb.checked = false;
    cb.closest('.pg-card')?.classList.remove('pg-selected');
  });

  if (profile.tools === null) {
    document.querySelectorAll('#parallel-subtool-grid .pg-checkbox').forEach(cb => {
      cb.checked = true;
      cb.closest('.pg-card')?.classList.add('pg-selected');
    });
  } else {
    document.querySelectorAll('#parallel-subtool-grid .pg-card').forEach(card => {
      const name = card.querySelector('.pg-card-name')?.textContent?.trim();
      if (profile.tools.includes(name)) {
        const cb = card.querySelector('.pg-checkbox');
        if (cb) { cb.checked = true; card.classList.add('pg-selected'); }
      }
    });
  }

  updateParallelCount();

  document.querySelectorAll('.pp-btn').forEach(btn => {
    btn.classList.toggle('pp-btn-active', btn.dataset.id === id);
  });
}


function streamCmd(cmd, requestId, onData, onError) {
  const controller = new AbortController();

  // Debe estar por encima del timeout del backend para Amass
  const frontendTimeoutMs = 930_000; // 15m 30s
  const stallTimeoutMs = 240_000;    // 4 min sin datos antes de abortar

  let finished = false;

  const frontendTimeout = setTimeout(() => {
    if (finished) return;
    controller.abort();
    onError('Timeout del frontend: la ejecución tardó demasiado');
  }, frontendTimeoutMs);

  fetch('/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cmd, request_id: requestId }),
    signal: controller.signal
  })
    .then(async (res) => {
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || 'Error HTTP');
      }

      if (!res.body) {
        throw new Error('La respuesta no contiene stream');
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      let stallTimer = null;

      function clearAllTimers() {
        clearTimeout(frontendTimeout);
        clearTimeout(stallTimer);
      }

      function resetStall() {
        clearTimeout(stallTimer);
        stallTimer = setTimeout(() => {
          if (finished) return;
          controller.abort();
          onError('Timeout por inactividad: no llegaron datos del stream durante demasiado tiempo');
        }, stallTimeoutMs);
      }

      resetStall();

      function processChunk(chunk) {
        buffer += decoder.decode(chunk, { stream: true });
        const events = buffer.split('\n\n');
        buffer = events.pop() || '';

        events.forEach(eventBlock => {
          const dataLines = eventBlock
            .split('\n')
            .filter(line => line.startsWith('data:'))
            .map(line => line.slice(5).trim());

          if (!dataLines.length) return;

          const payload = dataLines.join('\n');

          try {
            const msg = JSON.parse(payload);

            onData(msg);

            if (msg.type === 'done') {
              finished = true;
              clearAllTimers();
              try { reader.cancel(); } catch (_) {}
            }
          } catch (_) {
            // Ignorar eventos mal formados sin romper el stream
          }
        });
      }

      async function readLoop() {
        try {
          while (!finished) {
            const { done, value } = await reader.read();

            if (done) {
              if (!finished && buffer.trim()) {
                processChunk(new Uint8Array());
              }
              clearAllTimers();
              break;
            }

            resetStall();
            processChunk(value);
          }
        } catch (err) {
          clearAllTimers();
          if (err.name !== 'AbortError' && !finished) {
            onError(err.message || 'Error leyendo el stream');
          }
        }
      }

      readLoop();
    })
    .catch(err => {
      clearTimeout(frontendTimeout);
      if (err.name !== 'AbortError') {
        onError(err.message || 'Error de red');
      }
    });

  return controller;
}


// ── Toast notification ────────────────────────────────────────────────────────
function showToast(message, type = 'success', duration = 4000) {
  // Remove any existing toast
  const existing = document.getElementById('aletheia-toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.id = 'aletheia-toast';
  toast.className = `aletheia-toast aletheia-toast-${type}`;
  toast.innerHTML = `
    <span class="toast-icon">${type === 'success' ? '✓' : type === 'error' ? '✖' : 'ℹ'}</span>
    <span class="toast-msg">${escHtml(message)}</span>
    <button class="toast-close" onclick="this.closest('.aletheia-toast').remove()">×</button>
  `;

  document.body.appendChild(toast);

  // Trigger animation
  requestAnimationFrame(() => {
    requestAnimationFrame(() => toast.classList.add('toast-visible'));
  });

  // Auto-dismiss
  setTimeout(() => {
    toast.classList.remove('toast-visible');
    setTimeout(() => toast.remove(), 350);
  }, duration);
}

function setStatus(tool, state) {
  const running = $(`sr-${tool}`);
  const done = $(`sd-${tool}`);
  const idle = $(`ss-${tool}`);

  if (state === 'running') startTimer(tool);

  let elapsed = '';
  if (state === 'done') {
    elapsed = getElapsed(tool);
    stopTimer(tool);
  }

  if (state === 'idle') stopTimer(tool);

  if (running) running.style.display = state === 'running' ? 'flex' : 'none';
  if (done) done.style.display = state === 'done' ? 'inline-flex' : 'none';

  if (state === 'done') {
    const et = $(`et-${tool}`);
    if (et) et.textContent = elapsed ? `(${elapsed})` : '';

    const toolName = document.querySelector(`#panel-${tool} .page-title`)?.childNodes[0]?.textContent?.trim() || tool;
    showToast(`${toolName} completado${elapsed ? ` en ${elapsed}` : ''}`, 'success');
  }

  if (idle) idle.style.display = state === 'running' || state === 'done' ? 'none' : 'inline';
}

function stopTool(tool) {
  const requestId = runningRequests[tool];
  stopTimer(tool);

  if (!requestId) {
    resetBtn(tool);
    const idle = $(`ss-${tool}`);
    if ($(`sr-${tool}`)) $(`sr-${tool}`).style.display = 'none';
    if (idle) { idle.style.display = 'inline'; idle.textContent = '⬛ Detenido'; }
    return;
  }

  fetch('/stop', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_id: requestId })
  }).finally(() => {
    resetBtn(tool);
    stopTimer(tool);

    const running = $(`sr-${tool}`);
    const done    = $(`sd-${tool}`);
    const idle    = $(`ss-${tool}`);

    if (running) running.style.display = 'none';
    if (done)    done.style.display    = 'none';
    if (idle)    { idle.style.display = 'inline'; idle.textContent = '⬛ Detenido'; }

    delete runningRequests[tool];
  });
}

function resetBtn(tool) {
  const runBtn = $(`run-${tool}`);
  const stopBtn = $(`stop-${tool}`);

  if (runBtn) runBtn.disabled = false;
  if (stopBtn) stopBtn.style.display = 'none';
}

function clearOut(tool) {
  setHtml(`results-${tool}`, makeInfoText(UI_TEXT.emptySummary));
  const _ro = $(`raw-out-${tool}`); if (_ro) _ro.innerHTML = '';
  const badge = document.querySelector(`#raw-${tool} .line-count-badge`);
  if (badge) badge.textContent = '';
  const et = $(`et-${tool}`); if (et) et.textContent = '';
  stopTimer(tool);
  setStatus(tool, 'idle');
  clearHistory(tool);
}

/* ── Historial (sessionStorage) ──────────────────────────────────────────── */

function _histKey(tool) { return `aletheia_hist_${tool}`; }

function saveHistory(tool) {
  const rawEl    = $(`raw-out-${tool}`);
  const parsedEl = $(`results-${tool}`);
  if (!rawEl || !rawEl.textContent.trim()) return;
  const rawLines = rawEl.textContent.split('\n');
  const entry = {
    tool,
    target:        target || '',
    timestamp:     new Date().toLocaleTimeString('es-ES'),
    rawText:       rawEl.textContent,
    rawHtml:       rawEl.innerHTML,
    parsedHtml:    parsedEl ? parsedEl.innerHTML : '',
    parsedItems:   parseOutput(tool, rawLines),
    structuredData: _structuredCache[tool] || null,
    elapsed:       ($(`et-${tool}`) || {}).textContent || '',
  };
  try { sessionStorage.setItem(_histKey(tool), JSON.stringify(entry)); } catch(_) {}
  updateHomeActivity();
}

function restoreHistory(tool) {
  try {
    const raw = sessionStorage.getItem(_histKey(tool));
    if (!raw) return false;
    const entry = JSON.parse(raw);
    const rawEl    = $(`raw-out-${tool}`);
    const parsedEl = $(`results-${tool}`);
    if (rawEl)    rawEl.innerHTML    = entry.rawHtml    || '';
    if (parsedEl) parsedEl.innerHTML = entry.parsedHtml || '';
    // line count badge
    const lines = (entry.rawText || '').split('\n').filter(Boolean).length;
    const badge = document.querySelector(`#raw-${tool} .line-count-badge`);
    if (badge && lines) badge.textContent = lines;
    // elapsed
    const et = $(`et-${tool}`);
    if (et && entry.elapsed) et.textContent = entry.elapsed;
    setStatus(tool, 'done');
    const histBadge = $(`hist-badge-${tool}`);
    if (histBadge) {
      histBadge.textContent = `♻ ${entry.target ? entry.target + ' · ' : ''}${entry.timestamp}`;
      histBadge.style.display = 'inline-flex';
    }
    const dlBtn = $(`dl-btn-${tool}`);
    if (dlBtn) dlBtn.style.display = 'inline-flex';
    return true;
  } catch(_) { return false; }
}

function clearHistory(tool) {
  try { sessionStorage.removeItem(_histKey(tool)); } catch(_) {}
  const histBadge = $(`hist-badge-${tool}`);
  if (histBadge) histBadge.style.display = 'none';
  const dlBtn = $(`dl-btn-${tool}`);
  if (dlBtn) dlBtn.style.display = 'none';
}

/* ── Exportar output (PDF via print) ──────────────────────────────────────── */

function downloadOut(tool) {
  const rawEl    = $(`raw-out-${tool}`);
  const parsedEl = $(`results-${tool}`);
  if (!rawEl || !rawEl.textContent.trim()) return;

  const meta   = toolMeta[tool] || {};
  const title  = `Aletheia — ${meta.title || tool}`;
  const date   = new Date().toLocaleString('es-ES');
  const tgt    = target || '—';
  const rawTxt = rawEl.textContent;

  // Serialize parsed section (strip inline styles for cleaner print)
  const parsedHtml = parsedEl ? parsedEl.innerHTML : '';

  const html = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>${title} — ${tgt}</title>
<style>
  @page{size:A4 portrait;margin:2.5cm 2cm 2.2cm 2cm}
  *{box-sizing:border-box;margin:0;padding:0;-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}
  body{font-family:'Segoe UI',Helvetica,Arial,sans-serif;font-size:11px;color:#1C0500;background:#F9F5F4}
  .print-hdr{display:none;position:fixed;top:0;left:0;right:0;padding:6px 2cm;background:#1C0500;color:#9A6055;font-size:8pt;font-family:Arial,sans-serif;justify-content:space-between;align-items:center}
  .print-hdr strong{color:#F3EEEC}
  .print-ftr{display:none;position:fixed;bottom:0;left:0;right:0;padding:5px 2cm;border-top:1px solid #d0d0c8;font-size:8pt;font-family:Arial,sans-serif;color:#9A6055;justify-content:space-between;background:#F9F5F4}
  .cover{background:#1C0500;color:#fff;padding:44px 48px 36px;position:relative;overflow:hidden;break-after:page}
  .cover-accent{position:absolute;left:0;top:0;bottom:0;width:5px;background:linear-gradient(180deg,#BD1D00,#E84020)}
  .cover-brand{font-size:9px;font-weight:700;letter-spacing:.28em;text-transform:uppercase;color:#9A6055;margin-bottom:20px}
  .cover-badge{display:inline-block;background:#BD1D00;color:#fff;font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;padding:3px 10px;border-radius:999px;margin-bottom:14px}
  .cover-title{font-size:22px;font-weight:800;color:#fff;line-height:1.25;margin-bottom:4px}
  .cover-meta{display:flex;gap:24px;font-size:9.5px;color:#9A6055;margin-top:16px;padding-top:16px;border-top:1px solid rgba(189,29,0,.25)}
  .cover-meta b{color:#F3EEEC}
  .rpt-body{padding:32px 0;background:#F9F5F4}
  .section-hdr{position:relative;padding-left:14px;margin:28px 0 14px;font-size:0.58rem;font-weight:800;letter-spacing:3px;text-transform:uppercase;color:#9A6055;display:flex;align-items:center;gap:10px}
  .section-hdr::before{content:'';position:absolute;left:0;top:50%;transform:translateY(-50%);width:4px;height:13px;background:linear-gradient(180deg,#BD1D00,#E84020);border-radius:2px}
  .section-hdr-label{font-size:10.5px;font-weight:800;color:#1C0500;letter-spacing:0}
  .card{background:#fff;border:1px solid rgba(189,29,0,.09);border-radius:14px;padding:20px 22px;margin-bottom:12px;box-shadow:0 6px 18px rgba(189,29,0,.06);break-inside:avoid}
  .parsed-section table{width:100%;border-collapse:collapse;font-size:10px;border-radius:8px;overflow:hidden}
  .parsed-section td,.parsed-section th{border:1px solid rgba(189,29,0,.10);padding:6px 10px}
  .parsed-section th{background:#FBF2F0;font-weight:700;color:#3D1510;font-size:9px;text-transform:uppercase;letter-spacing:.04em}
  .parsed-section tr:nth-child(even) td{background:#FBF2F0}
  .parsed-section .ui-message{color:#9A6055;font-style:italic}
  .raw-label{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#F3EEEC;background:#3D1510;padding:7px 14px;border-radius:8px 8px 0 0;margin-top:0}
  pre{white-space:pre-wrap;word-break:break-all;font-family:'Courier New',monospace;font-size:8.5px;background:#130400;color:#f0e8e5;border-radius:0 0 8px 8px;padding:14px;line-height:1.7;margin-top:0}
  @media print{
    body{background:#F9F5F4;padding-top:1.1cm;padding-bottom:0.9cm}
    .print-hdr,.print-ftr{display:flex}
  }
</style>
</head>
<body>
  <div class="print-hdr"><strong>Aletheia OSINT Platform</strong><span>CONFIDENCIAL — USO INTERNO</span></div>
  <div class="print-ftr"><span>Informe de herramienta — ${tgt}</span><span>${date}</span></div>
  <div class="cover">
    <div class="cover-accent"></div>
    <div class="cover-brand">Aletheia OSINT Platform</div>
    <div class="cover-badge">${tool}</div>
    <div class="cover-title">${title}</div>
    <div class="cover-meta">
      <span><b>Objetivo</b> ${tgt}</span>
      <span><b>Fecha</b> ${date}</span>
    </div>
  </div>
  <div class="rpt-body">
    <div class="section-hdr"><span class="section-hdr-label">Resumen</span></div>
    <div class="card"><div class="parsed-section">${parsedHtml}</div></div>
    <div class="section-hdr"><span class="section-hdr-label">Output técnico completo</span></div>
    <div class="raw-label">Terminal</div>
    <pre>${rawTxt.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</pre>
  </div>
</body>
</html>`;

  const win = window.open('', '_blank', 'width=900,height=700');
  if (!win) return;
  win.document.write(html);
  win.document.close();
  win.focus();
  setTimeout(() => win.print(), 600);
}

/* ── Executive PDF report ────────────────────────────────────────────────── */

function generateExecutiveReport() {
  const scope   = getScope() || {};
  const date    = new Date().toLocaleString('es-ES');
  const dateISO = new Date().toISOString().slice(0, 10);

  function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

  // ── Collect all data sources ───────────────────────────────────────────────
  const toolEntries = toolList.map(t => {
    try {
      const raw = sessionStorage.getItem(_histKey(t));
      if (!raw) return null;
      const e = JSON.parse(raw);
      if (!e.parsedItems && e.rawText) e.parsedItems = parseOutput(t, e.rawText.split('\n'));
      return { ...e, tool: t };
    } catch(_) { return null; }
  }).filter(Boolean);

  let parallelRuns = [];
  try {
    parallelRuns = JSON.parse(sessionStorage.getItem('aletheia_parallel_runs') || '[]');
    parallelRuns = parallelRuns.map(r => {
      if (!r.parsedItems && r.rawText) r.parsedItems = parseOutput(r.tool, r.rawText.split('\n'));
      return r;
    });
  } catch(_) {}

  let shodanData = null, vtData = null;
  try { shodanData = JSON.parse(sessionStorage.getItem('aletheia_shodan_data') || 'null'); } catch(_) {}
  try { vtData     = JSON.parse(sessionStorage.getItem('aletheia_vt_data')     || 'null'); } catch(_) {}

  // ── Aggregate intelligence ─────────────────────────────────────────────────
  const aggHosts  = [];
  const aggIPs    = [];
  const aggEmails = [];

  function collectEntry(parsedItems, structuredData, label) {
    (parsedItems || []).forEach(g => {
      (g.items || []).forEach(item => {
        if (g.type === 'host')  aggHosts.push({ value: item, source: label });
        else if (g.type === 'ip')    aggIPs.push({ value: item, source: label });
        else if (g.type === 'email') aggEmails.push({ value: item, source: label });
      });
    });
    // Map host→IP from theHarvester structuredData
    if (structuredData?.tool === 'theharvester') {
      (structuredData.hosts_with_ip || []).forEach(entry => {
        if (entry.includes(':')) {
          const [host, ip] = entry.split(':');
          if (host && !aggHosts.some(h => h.value === host.trim()))
            aggHosts.push({ value: host.trim(), ip: ip.trim(), source: label });
          if (ip && !aggIPs.some(h => h.value === ip.trim()))
            aggIPs.push({ value: ip.trim(), source: label });
        }
      });
    }
  }

  function stripEmoji(s) { return String(s).replace(/[\u{1F300}-\u{1FFFF}\u{2600}-\u{27BF}]/gu, '').trim(); }

  toolEntries.forEach(e => collectEntry(e.parsedItems, e.structuredData, stripEmoji(toolMeta[e.tool]?.title || e.tool)));
  parallelRuns.forEach(r => collectEntry(r.parsedItems, r.structuredData, `${stripEmoji(r.toolTitle || r.tool)} — ${r.subtoolName}`));

  function dedup(arr) {
    const seen = new Set();
    return arr.filter(e => { if (seen.has(e.value)) return false; seen.add(e.value); return true; });
  }
  const uniqHosts  = dedup(aggHosts);
  const uniqIPs    = dedup(aggIPs);
  const uniqEmails = dedup(aggEmails);
  if (shodanData?.ip && !uniqIPs.some(e => e.value === shodanData.ip))
    uniqIPs.push({ value: shodanData.ip, source: 'Shodan' });

  const cves     = shodanData?.vulns || [];
  const vtVerdict = vtData?.verdict || null;
  const toolsRun = toolEntries.length + parallelRuns.length + (shodanData ? 1 : 0) + (vtData ? 1 : 0);

  // ── PDF render helpers ─────────────────────────────────────────────────────
  function renderGroup(group) {
    if (!group?.items?.length) return '';
    const { title, icon, type, items } = group;
    let body = '';
    if (type === 'port-open' || type === 'port-filtered') {
      const rows = items.map(line => {
        const m = line.match(/(\d+)\/(tcp|udp)\s+(\S+)\s*(\S*)\s*(.*)/i);
        if (!m) return `<tr><td colspan="4">${esc(line)}</td></tr>`;
        const [, port, proto, state, svc, ver] = m;
        return `<tr><td><b>${esc(port)}/${esc(proto)}</b></td><td>${esc(state)}</td><td>${esc(svc)}</td><td>${esc(ver.trim())}</td></tr>`;
      }).join('');
      body = `<table class="fi-table"><thead><tr><th>Puerto</th><th>Estado</th><th>Servicio</th><th>Versión</th></tr></thead><tbody>${rows}</tbody></table>`;
    } else if (type === 'generic') {
      const rows = items.map(item => {
        const ci = item.indexOf(':');
        if (ci > 0) {
          return `<tr><td class="fi-key">${esc(item.slice(0, ci).trim())}</td><td>${esc(item.slice(ci + 1).trim())}</td></tr>`;
        }
        return `<tr><td colspan="2">${esc(item)}</td></tr>`;
      }).join('');
      body = `<table class="fi-table fi-kv"><tbody>${rows}</tbody></table>`;
    } else {
      const rows = items.map(item => `<tr><td>${esc(item)}</td></tr>`).join('');
      body = `<table class="fi-table fi-list"><tbody>${rows}</tbody></table>`;
    }
    return `<div class="fi-group"><div class="fi-group-hdr">${esc(icon)} ${esc(title)}</div>${body}</div>`;
  }

  function renderFindings(parsedItems) {
    if (!parsedItems?.length) return '<p class="dim">Sin datos procesados para esta herramienta.</p>';
    const out = parsedItems.map(g => renderGroup(g)).join('');
    return out || '<p class="dim">Sin resultados.</p>';
  }

  function aggTable(items, colHeaders) {
    if (!items.length) return '<p class="dim">Ninguno detectado en esta sesión.</p>';
    const ths = colHeaders.map(c => `<th>${esc(c)}</th>`).join('');
    const trs = items.map(e => {
      if (colHeaders.length === 3)
        return `<tr><td>${esc(e.value)}</td><td>${esc(e.ip||'—')}</td><td class="src-cell">${esc(e.source)}</td></tr>`;
      return `<tr><td>${esc(e.value)}</td><td class="src-cell">${esc(e.source)}</td></tr>`;
    }).join('');
    return `<table class="agg-table"><thead><tr>${ths}</tr></thead><tbody>${trs}</tbody></table>`;
  }

  // ── Section 4: per-tool findings ───────────────────────────────────────────
  let toolSections = '';
  let sIdx = 1;

  toolEntries.forEach(e => {
    const title = toolMeta[e.tool]?.title || e.tool;
    toolSections += `
      <div class="card rpt-section">
        <div class="rpt-section-hdr">
          <span class="rpt-section-num">4.${sIdx++}</span>
          <span class="rpt-section-title">${esc(stripEmoji(title))}</span>
          <span class="rpt-section-meta">${esc(e.target)} · ${esc(e.timestamp)} · ${esc(e.elapsed)}</span>
        </div>
        ${renderFindings(e.parsedItems)}
      </div>`;
  });

  parallelRuns.forEach(r => {
    toolSections += `
      <div class="card rpt-section">
        <div class="rpt-section-hdr">
          <span class="rpt-section-num">4.${sIdx++}</span>
          <span class="rpt-section-title">${esc(stripEmoji(r.toolTitle || r.tool))} — ${esc(r.subtoolName)}</span>
          <span class="rpt-section-meta">${esc(r.target)} · ${esc(r.elapsed)}${r.hadError ? ' · ⚠ con errores' : ''}</span>
        </div>
        ${renderFindings(r.parsedItems)}
      </div>`;
  });

  if (shodanData) {
    const svcRows = (shodanData.services || []).slice(0, 40).map(s => {
      const prod = [s.product, s.version].filter(Boolean).join(' ');
      return `<tr><td><b>${s.port||'—'}</b></td><td>${esc(s.transport||'tcp')}</td><td>${esc(prod||s.module||'—')}</td><td class="banner-cell">${esc((s.banner||'').split('\n')[0])}</td></tr>`;
    }).join('');
    const cveChips = cves.length ? cves.map(id => `<span class="rpt-cve">${esc(id)}</span>`).join(' ') : '<em class="dim">Ninguno detectado</em>';
    toolSections += `
      <div class="card rpt-section">
        <div class="rpt-section-hdr">
          <span class="rpt-section-num">4.${sIdx++}</span>
          <span class="rpt-section-title">Shodan — Exposición de red</span>
          <span class="rpt-section-meta">IP: ${esc(shodanData.ip)} · ${esc(shodanData.org||'—')} · ${esc(shodanData.country||'—')}</span>
        </div>
        ${svcRows ? `<table class="fi-table"><thead><tr><th>Puerto</th><th>Proto</th><th>Servicio / Producto</th><th>Banner</th></tr></thead><tbody>${svcRows}</tbody></table>` : '<p class="dim">Sin servicios expuestos.</p>'}
        <div style="margin-top:12px"><div class="fi-group-hdr" style="border-radius:6px 6px 0 0">CVEs detectados</div><div style="padding:8px 12px;background:#FBF2F0;border:1px solid rgba(189,29,0,.10);border-top:none;border-radius:0 0 6px 6px">${cveChips}</div></div>
      </div>`;
  }

  if (vtData) {
    const vColor = vtData.verdict === 'malicious' ? '#DC2626' : vtData.verdict === 'suspicious' ? '#D97706' : '#16A34A';
    const vBg    = vtData.verdict === 'malicious' ? '#fff5f5' : vtData.verdict === 'suspicious' ? '#fffaf3' : '#f5fff8';
    const stats  = vtData.stats || {};
    const flagged = (vtData.flagged || []).slice(0, 20);
    toolSections += `
      <div class="card rpt-section">
        <div class="rpt-section-hdr">
          <span class="rpt-section-num">4.${sIdx++}</span>
          <span class="rpt-section-title">VirusTotal — Reputación</span>
          <span class="rpt-section-meta">${esc(vtData._target||'—')} · ${esc(vtData.type)}</span>
        </div>
        <div style="background:${vBg};border:1px solid ${vColor};border-radius:10px;padding:14px 18px;display:flex;align-items:center;gap:20px;margin-bottom:12px">
          <div style="font-size:22px;font-weight:800;color:${vColor};letter-spacing:.04em">${esc((vtData.verdict||'').toUpperCase())}</div>
          <div style="font-size:10px;color:#3D1510">
            <b>${stats.malicious||0}</b> motores maliciosos ·
            <b>${stats.suspicious||0}</b> sospechosos ·
            <b>${stats.harmless||0}</b> limpios
            <span style="color:#9A6055"> de ${vtData.total_engines||0} motores totales</span>
          </div>
        </div>
        ${flagged.length ? `<table class="fi-table" style="border-radius:8px;overflow:hidden"><thead><tr><th>Motor antivirus</th><th>Resultado</th></tr></thead><tbody>${
          flagged.map(f => `<tr><td>${esc(f.engine)}</td><td style="color:${f.category==='malicious'?'#DC2626':'#D97706'};font-weight:600">${esc(f.result||f.category)}</td></tr>`).join('')
        }</tbody></table>` : ''}
      </div>`;
  }

  // ── Appendix: raw terminal output ──────────────────────────────────────────
  let appendix = '';
  let aIdx = 1;
  toolEntries.forEach(e => {
    appendix += `
      <div class="rpt-appendix-tool">
        <div class="rpt-appendix-title">A.${aIdx++} ${esc(stripEmoji(toolMeta[e.tool]?.title || e.tool))} — ${esc(e.target)} — ${esc(e.timestamp)}</div>
        <pre>${esc((e.rawText||'').slice(0,8000))}${(e.rawText||'').length>8000?'\n[... truncado ...]':''}</pre>
      </div>`;
  });
  parallelRuns.forEach(r => {
    appendix += `
      <div class="rpt-appendix-tool">
        <div class="rpt-appendix-title">A.${aIdx++} ${esc(r.subtoolName)} (${esc(stripEmoji(r.toolTitle||r.tool))}) — ${esc(r.target)}</div>
        <pre>${esc((r.rawText||'').slice(0,6000))}${(r.rawText||'').length>6000?'\n[... truncado ...]':''}</pre>
      </div>`;
  });

  // ── Build HTML ─────────────────────────────────────────────────────────────
  const html = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Informe OSINT — ${esc(scope.caseName || 'Análisis')}</title>
<style>
@page{size:A4 portrait;margin:2.5cm 2cm 2.2cm 2cm}
*{box-sizing:border-box;margin:0;padding:0;-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}
body{font-family:'Segoe UI',Helvetica,Arial,sans-serif;font-size:11px;color:#1C0500;background:#F9F5F4}
a{color:#BD1D00}

/* Cabecera y pie repetidos en cada hoja (sólo en impresión) */
.print-hdr{display:none;position:fixed;top:0;left:0;right:0;padding:6px 2cm;background:#1C0500;color:#9A6055;font-size:8pt;font-family:Arial,sans-serif;justify-content:space-between;align-items:center}
.print-hdr strong{color:#F3EEEC}
.print-ftr{display:none;position:fixed;bottom:0;left:0;right:0;padding:5px 2cm;border-top:1px solid #d0d0c8;font-size:8pt;font-family:Arial,sans-serif;color:#9A6055;justify-content:space-between;background:#F9F5F4}

/* Cover */
.cover{
  background:#1C0500;color:#fff;
  padding:64px 52px;
  break-after:page;page-break-after:always;
  display:flex;flex-direction:column;justify-content:space-between;
  position:relative;overflow:hidden;
}
.cover-accent{
  position:absolute;left:0;top:0;bottom:0;width:5px;
  background:linear-gradient(180deg,#BD1D00,#E84020);
}
.cover-brand{font-size:9px;font-weight:700;letter-spacing:.28em;text-transform:uppercase;color:#9A6055;margin-bottom:52px}
.cover-badge{
  display:inline-block;background:#BD1D00;color:#fff;
  font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
  padding:3px 10px;border-radius:999px;margin-bottom:18px
}
.cover-title{font-size:30px;font-weight:800;color:#fff;line-height:1.25;margin-bottom:8px}
.cover-client{font-size:14px;color:#C07060}
.cover-bottom{border-top:1px solid rgba(189,29,0,.25);padding-top:22px}
.cover-meta{display:grid;grid-template-columns:repeat(3,1fr);gap:14px 28px;font-size:9.5px;color:#9A6055}
.cover-meta-item b{display:block;color:#F3EEEC;font-size:10.5px;margin-bottom:2px}

/* Body */
.rpt-body{padding:36px 0;background:#F9F5F4}

/* Section title — matches .section-title from web */
.rpt-h1{
  position:relative;padding-left:16px;
  margin:36px 0 18px;
  font-size:0.6rem;font-weight:800;letter-spacing:3px;text-transform:uppercase;color:#9A6055;
  display:flex;align-items:center;gap:12px;
}
.rpt-h1::before{
  content:'';position:absolute;left:0;top:50%;transform:translateY(-50%);
  width:4px;height:14px;
  background:linear-gradient(180deg,#BD1D00,#E84020);border-radius:2px;
}
.rpt-h1 .h1-num{
  font-size:9px;font-weight:700;
  background:linear-gradient(135deg,#BD1D00,#8B1400);
  color:#fff;padding:2px 9px;border-radius:999px;letter-spacing:.04em;
}
.rpt-h1 .h1-label{font-size:11px;font-weight:800;color:#1C0500;letter-spacing:0}

/* Card — matches .stat-card / .home-card from web */
.card{
  background:#fff;border:1px solid rgba(189,29,0,.09);
  border-radius:14px;padding:20px 22px;margin-bottom:14px;
  box-shadow:0 8px 24px rgba(189,29,0,.06);
}

/* Summary cards */
.sum-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px}
.sum-card{
  background:#fff;border:1px solid rgba(189,29,0,.10);
  border-radius:12px;padding:16px 10px;text-align:center;
  box-shadow:0 4px 14px rgba(189,29,0,.05);
}
.sum-card.red{border-color:rgba(220,38,38,.3);background:#fff5f5}
.sum-card.amber{border-color:rgba(217,119,6,.3);background:#fffaf3}
.sum-card.green{border-color:rgba(22,163,74,.25);background:#f5fff8}
.sum-num{font-size:26px;font-weight:800;color:#1C0500;line-height:1}
.sum-num.red{color:#DC2626}
.sum-num.amber{color:#D97706}
.sum-num.green{color:#16A34A}
.sum-lbl{font-size:8px;text-transform:uppercase;letter-spacing:.08em;color:#9A6055;margin-top:7px}

/* Scope table */
.scope-table{width:100%;border-collapse:collapse;font-size:10.5px}
.scope-table td{padding:8px 13px;border:1px solid rgba(189,29,0,.12)}
.scope-table .sk{font-weight:700;color:#3D1510;background:#FBF2F0;width:180px;text-transform:uppercase;font-size:9px;letter-spacing:.05em}

/* Section block */
.rpt-section{margin-bottom:14px}
.rpt-section-hdr{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.rpt-section-num{
  font-size:9px;font-weight:700;
  background:linear-gradient(135deg,#BD1D00,#8B1400);
  color:#fff;padding:2px 9px;border-radius:999px;letter-spacing:.04em;white-space:nowrap;
}
.rpt-section-title{font-size:12px;font-weight:700;color:#1C0500}
.rpt-section-meta{font-size:9px;color:#9A6055;margin-left:auto;text-align:right}

/* Aggregated tables */
.agg-table{width:100%;border-collapse:collapse;font-size:10px;border-radius:10px;overflow:hidden}
.agg-table th{background:#3D1510;color:#F3EEEC;padding:7px 12px;text-align:left;font-size:9px;letter-spacing:.05em;font-weight:700}
.agg-table td{padding:6px 12px;border-bottom:1px solid rgba(189,29,0,.07);vertical-align:top;background:#fff}
.agg-table tr:nth-child(even) td{background:#FBF2F0}
.src-cell{color:#9A6055;font-size:9px}

/* Finding groups */
.fi-group{margin-bottom:10px;border-radius:10px;overflow:hidden;border:1px solid rgba(189,29,0,.10)}
.fi-group-hdr{font-size:9.5px;font-weight:700;color:#3D1510;background:#FBF2F0;padding:6px 12px;border-bottom:1px solid rgba(189,29,0,.10)}
.fi-table{width:100%;border-collapse:collapse;font-size:10px}
.fi-table th{background:#F3EEEC;color:#3D1510;padding:5px 12px;text-align:left;font-size:9px;letter-spacing:.04em;font-weight:700;border-bottom:1px solid rgba(189,29,0,.08)}
.fi-table td{padding:5px 12px;border-bottom:1px solid rgba(189,29,0,.05);vertical-align:top;background:#fff}
.fi-table tr:last-child td{border-bottom:none}
.fi-table tr:nth-child(even) td{background:#FBF2F0}
.fi-key{font-weight:600;color:#3D1510;background:#F3EEEC!important;width:160px;white-space:nowrap;font-size:9.5px}
.fi-list td{font-family:'Courier New',monospace;font-size:9.5px}
.banner-cell{font-family:'Courier New',monospace;font-size:8.5px;color:#9A6055;max-width:200px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* CVE chips */
.rpt-cve{
  display:inline-block;background:rgba(220,38,38,.08);
  border:1px solid rgba(220,38,38,.22);color:#DC2626;
  border-radius:999px;padding:2px 9px;
  font-family:monospace;font-size:9px;font-weight:700;margin:2px;
}

/* Appendix */
.rpt-appendix-note{font-size:9.5px;color:#9A6055;font-style:italic;margin-bottom:18px;padding:10px 14px;background:#FBF2F0;border-left:4px solid #BD1D00;border-radius:0 8px 8px 0}
.rpt-appendix-tool{margin-bottom:22px}
.rpt-appendix-title{font-size:9.5px;font-weight:700;background:#3D1510;color:#F3EEEC;padding:7px 14px;border-radius:8px 8px 0 0}
pre{white-space:pre-wrap;word-break:break-all;font-family:'Courier New',monospace;font-size:8px;background:#130400;color:#f0e8e5;border-radius:0 0 8px 8px;padding:14px;line-height:1.7}

.body-text{font-size:10.5px;color:#3D1510;line-height:1.8;margin-bottom:10px}
.dim{color:#9A6055;font-style:italic;font-size:10px}

@media print{
  body{background:#F9F5F4;padding-top:1.1cm;padding-bottom:0.9cm}
  .print-hdr,.print-ftr{display:flex}
  .cover{page-break-after:always}
  .card,.rpt-section{page-break-inside:avoid;break-inside:avoid}
  pre{max-height:none}
}
</style>
</head>
<body>

<div class="print-hdr"><strong>Aletheia OSINT Platform</strong><span>CONFIDENCIAL — USO INTERNO</span></div>
<div class="print-ftr"><span>Informe de reconocimiento externo — ${esc(scope.client || '')}</span><span>${date}</span></div>

<!-- COVER -->
<div class="cover">
  <div class="cover-accent"></div>
  <div>
    <div class="cover-brand">Aletheia OSINT Platform</div>
    <div class="cover-badge">CONFIDENCIAL</div>
    <div class="cover-title">${esc(scope.caseName || 'Informe de reconocimiento externo')}</div>
    <div class="cover-client">${esc(scope.client || 'Cliente no especificado')}</div>
  </div>
  <div class="cover-bottom">
    <div class="cover-meta">
      <div class="cover-meta-item"><b>Fecha del informe</b>${date}</div>
      <div class="cover-meta-item"><b>Responsable</b>${esc(scope.responsable || '—')}</div>
      <div class="cover-meta-item"><b>Expiración del alcance</b>${esc(scope.expiry || '—')}</div>
      <div class="cover-meta-item"><b>Tipo de análisis</b>${scope.scanType === 'passive' ? 'Solo pasivo' : 'Activo permitido'}</div>
      <div class="cover-meta-item"><b>Dominios analizados</b>${esc((scope.domains||[]).join(', ') || '—')}</div>
      <div class="cover-meta-item"><b>Rangos IP</b>${esc((scope.ipRanges||[]).join(', ') || '—')}</div>
    </div>
  </div>
</div>

<!-- BODY -->
<div class="rpt-body">

  <!-- 01 SCOPE -->
  <div class="rpt-h1"><span class="h1-num">01</span><span class="h1-label">Alcance del encargo</span></div>
  <div class="card" style="padding:0;overflow:hidden">
    <table class="scope-table">
      <tr><td class="sk">Expediente</td><td>${esc(scope.caseName||'—')}</td></tr>
      <tr><td class="sk">Cliente</td><td>${esc(scope.client||'—')}</td></tr>
      <tr><td class="sk">Responsable</td><td>${esc(scope.responsable||'—')}</td></tr>
      <tr><td class="sk">Dominios aprobados</td><td>${esc((scope.domains||[]).join(', ')||'—')}</td></tr>
      <tr><td class="sk">Rangos IP aprobados</td><td>${esc((scope.ipRanges||[]).join(', ')||'—')}</td></tr>
      <tr><td class="sk">Modalidad</td><td>${scope.scanType === 'passive' ? 'Análisis pasivo (sin interacción directa)' : 'Análisis activo (interacción directa permitida)'}</td></tr>
      <tr><td class="sk">Expiración</td><td>${esc(scope.expiry||'—')}</td></tr>
      <tr><td class="sk">Fecha del análisis</td><td>${dateISO}</td></tr>
    </table>
  </div>

  <!-- 02 EXECUTIVE SUMMARY -->
  <div class="rpt-h1"><span class="h1-num">02</span><span class="h1-label">Resumen ejecutivo</span></div>
  <div class="sum-grid">
    <div class="sum-card">
      <div class="sum-num">${toolsRun}</div>
      <div class="sum-lbl">Herramientas ejecutadas</div>
    </div>
    <div class="sum-card">
      <div class="sum-num">${uniqHosts.length}</div>
      <div class="sum-lbl">Subdominios / hosts</div>
    </div>
    <div class="sum-card ${cves.length ? 'red' : 'green'}">
      <div class="sum-num ${cves.length ? 'red' : 'green'}">${cves.length}</div>
      <div class="sum-lbl">CVEs detectados</div>
    </div>
    <div class="sum-card ${vtVerdict === 'malicious' ? 'red' : vtVerdict === 'suspicious' ? 'amber' : 'green'}">
      <div class="sum-num ${vtVerdict === 'malicious' ? 'red' : vtVerdict === 'suspicious' ? 'amber' : 'green'}">${vtVerdict ? vtVerdict.toUpperCase() : '—'}</div>
      <div class="sum-lbl">Veredicto VirusTotal</div>
    </div>
  </div>
  <div class="card">
    <p class="body-text">
      En el marco del encargo <b>${esc(scope.caseName||'—')}</b> para <b>${esc(scope.client||'—')}</b>,
      se han ejecutado <b>${toolsRun}</b> módulos de reconocimiento sobre los activos aprobados.
      El análisis ha identificado <b>${uniqHosts.length}</b> subdominios o hosts,
      <b>${uniqIPs.length}</b> direcciones IP y
      <b>${uniqEmails.length}</b> correos electrónicos.
      ${cves.length ? `Se han detectado <b style="color:#DC2626">${cves.length} vulnerabilidades CVE</b> activas en el perímetro expuesto.` : 'No se han detectado CVEs activos mediante Shodan.'}
      ${vtVerdict === 'malicious' ? `VirusTotal califica el objetivo como <b style="color:#DC2626">MALICIOSO</b>.` : vtVerdict === 'suspicious' ? `VirusTotal califica el objetivo como <b style="color:#D97706">SOSPECHOSO</b>.` : ''}
    </p>
  </div>

  <!-- 03 CONSOLIDATED INTELLIGENCE -->
  <div class="rpt-h1"><span class="h1-num">03</span><span class="h1-label">Inteligencia consolidada</span></div>

  <div class="card">
    <div class="rpt-section-hdr">
      <span class="rpt-section-num">3.1</span>
      <span class="rpt-section-title">Subdominios y hosts descubiertos</span>
      <span class="rpt-section-meta">${uniqHosts.length} únicos</span>
    </div>
    ${aggTable(uniqHosts, ['Subdominio / Host', 'IP asociada', 'Fuente'])}
  </div>

  <div class="card">
    <div class="rpt-section-hdr">
      <span class="rpt-section-num">3.2</span>
      <span class="rpt-section-title">Direcciones IP identificadas</span>
      <span class="rpt-section-meta">${uniqIPs.length} únicas</span>
    </div>
    ${aggTable(uniqIPs, ['Dirección IP', 'Fuente'])}
  </div>

  <div class="card">
    <div class="rpt-section-hdr">
      <span class="rpt-section-num">3.3</span>
      <span class="rpt-section-title">Correos electrónicos hallados</span>
      <span class="rpt-section-meta">${uniqEmails.length} únicos</span>
    </div>
    ${aggTable(uniqEmails, ['Dirección de correo', 'Fuente'])}
  </div>

  ${cves.length ? `
  <div class="card">
    <div class="rpt-section-hdr">
      <span class="rpt-section-num">3.4</span>
      <span class="rpt-section-title">Vulnerabilidades CVE (Shodan)</span>
      <span class="rpt-section-meta">${cves.length} en IP ${esc(shodanData?.ip||'—')}</span>
    </div>
    <p class="body-text" style="margin-bottom:12px">Vulnerabilidades correlacionadas por Shodan con los servicios expuestos. Verificar aplicabilidad y priorizar remediación.</p>
    <div>${cves.map(id => `<span class="rpt-cve">${esc(id)}</span>`).join(' ')}</div>
  </div>` : ''}

  <!-- 04 PER-TOOL FINDINGS -->
  <div class="rpt-h1"><span class="h1-num">04</span><span class="h1-label">Hallazgos por herramienta</span></div>
  ${toolSections || '<div class="card"><p class="dim">No se han ejecutado herramientas en esta sesión.</p></div>'}

  <!-- APPENDIX -->
  ${appendix ? `
  <div class="rpt-h1"><span class="h1-num">A</span><span class="h1-label">Apéndice — Output técnico completo</span></div>
  <div class="rpt-appendix-note">Esta sección contiene el output en bruto de cada herramienta. Destinada a uso técnico, no a la lectura ejecutiva.</div>
  ${appendix}` : ''}

</div>
</body>
</html>`;

  const win = window.open('', '_blank', 'width=1100,height=850');
  if (!win) return;
  win.document.write(html);
  win.document.close();
  win.focus();
  setTimeout(() => win.print(), 700);
}

/* ── STIX 2.1 JSON export ────────────────────────────────────────────────── */

// STIX 2.1 namespace for deterministic SCO UUIDv5 IDs
const _STIX_NS = Uint8Array.from([
  0x00,0xab,0xed,0xb4, 0xaa,0x42,0x46,0x6c,
  0x9c,0x01,0xfe,0xd2, 0x33,0x15,0xa9,0xb7,
]);

function _uuid4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

async function _scoId(type, value) {
  const nameBytes = new TextEncoder().encode(JSON.stringify({ value }));
  const data = new Uint8Array(_STIX_NS.length + nameBytes.length);
  data.set(_STIX_NS);
  data.set(nameBytes, _STIX_NS.length);
  const h = new Uint8Array(await crypto.subtle.digest('SHA-1', data));
  h[6] = (h[6] & 0x0f) | 0x50;
  h[8] = (h[8] & 0x3f) | 0x80;
  const x = Array.from(h.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${type}--${x.slice(0,8)}-${x.slice(8,12)}-${x.slice(12,16)}-${x.slice(16,20)}-${x.slice(20)}`;
}

async function generateSTIX() {
  const scope = getScope() || {};
  const now   = new Date().toISOString();

  // ── Phase 1: collect all unique SCO values ──
  const seenIPs = new Set(), seenDomains = new Set(), seenEmails = new Set(), seenCves = new Set();
  const allIPs = [], allDomains = [], allEmails = [];

  const ipRe        = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
  const cveRe       = /CVE-\d{4}-\d{4,7}/gi;
  const emailRe     = /[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/gi;
  const privateIpRe = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.)/;

  function collectIP(ip)     { if (!privateIpRe.test(ip) && !seenIPs.has(ip))     { seenIPs.add(ip);         allIPs.push(ip); } }
  function collectDomain(d)  { if (!seenDomains.has(d))                            { seenDomains.add(d);       allDomains.push(d); } }
  function collectEmail(em)  { if (!seenEmails.has(em))                            { seenEmails.add(em);       allEmails.push(em); } }
  function collectCve(id)    { if (!seenCves.has(id))                              { seenCves.add(id); } }

  function collectFromText(rawText) {
    (rawText.match(ipRe)    || []).forEach(ip  => collectIP(ip));
    (rawText.match(emailRe) || []).forEach(em  => collectEmail(em.toLowerCase()));
    (rawText.match(cveRe)   || []).forEach(cve => collectCve(cve.toUpperCase()));
  }

  let shodanData = null, vtData = null;
  try { shodanData = JSON.parse(sessionStorage.getItem('aletheia_shodan_data') || 'null'); } catch(_) {}
  try { vtData     = JSON.parse(sessionStorage.getItem('aletheia_vt_data')     || 'null'); } catch(_) {}

  if (shodanData?.ip)                        collectIP(shodanData.ip);
  (shodanData?.hostnames || []).forEach(hn => collectDomain(hn));
  (shodanData?.vulns     || []).forEach(cv => collectCve(cv));

  toolList.forEach(tool => {
    try { const { rawText = '' } = JSON.parse(sessionStorage.getItem(_histKey(tool)) || '{}'); collectFromText(rawText); } catch(_) {}
  });
  try {
    JSON.parse(sessionStorage.getItem('aletheia_parallel_runs') || '[]').forEach(r => collectFromText(r.rawText || ''));
  } catch(_) {}

  (scope.domains || []).forEach(d => collectDomain(d));

  // ── Phase 2: generate deterministic UUIDv5 for all SCOs in parallel ──
  const [ipIds, domainIds, emailIds] = await Promise.all([
    Promise.all(allIPs.map(v     => _scoId('ipv4-addr',   v))),
    Promise.all(allDomains.map(v => _scoId('domain-name', v))),
    Promise.all(allEmails.map(v  => _scoId('email-addr',  v))),
  ]);

  const ipMap     = Object.fromEntries(allIPs.map((v, i)     => [v, ipIds[i]]));
  const domainMap = Object.fromEntries(allDomains.map((v, i) => [v, domainIds[i]]));
  const emailMap  = Object.fromEntries(allEmails.map((v, i)  => [v, emailIds[i]]));

  // ── Phase 3: build STIX objects ──
  const objects = [], reportRefs = [];
  function addObj(obj) { objects.push(obj); reportRefs.push(obj.id); return obj.id; }

  // Identity
  addObj({
    type: 'identity', spec_version: '2.1', id: `identity--${_uuid4()}`,
    name: scope.client || scope.caseName || 'Unknown Client',
    identity_class: 'organization', created: now, modified: now,
  });

  // SCO: ipv4-addr
  allIPs.forEach(ip => addObj({ type: 'ipv4-addr', spec_version: '2.1', id: ipMap[ip], value: ip }));

  // SCO: domain-name
  allDomains.forEach(d => addObj({ type: 'domain-name', spec_version: '2.1', id: domainMap[d], value: d }));

  // SCO: email-addr
  allEmails.forEach(e => addObj({ type: 'email-addr', spec_version: '2.1', id: emailMap[e], value: e }));

  // Shodan: network-traffic + observed-data
  if (shodanData?.ip) {
    const ipId = ipMap[shodanData.ip];
    const portRefs = [ipId];
    (shodanData.services || []).forEach(svc => {
      if (!svc.port) return;
      portRefs.push(addObj({
        type: 'network-traffic', spec_version: '2.1', id: `network-traffic--${_uuid4()}`,
        dst_ref: ipId, dst_port: svc.port, protocols: [svc.transport || 'tcp'],
      }));
    });
    addObj({
      type: 'observed-data', spec_version: '2.1', id: `observed-data--${_uuid4()}`,
      created: now, modified: now, first_observed: now, last_observed: now,
      number_observed: 1, object_refs: portRefs,
    });
  }

  // CVEs → vulnerability SDOs
  seenCves.forEach(cveId => addObj({
    type: 'vulnerability', spec_version: '2.1', id: `vulnerability--${_uuid4()}`,
    name: cveId, created: now, modified: now,
    external_references: [{ source_name: 'cve', external_id: cveId,
      url: `https://nvd.nist.gov/vuln/detail/${cveId}` }],
  }));

  // VirusTotal → indicator
  if (vtData && (vtData.verdict === 'malicious' || vtData.verdict === 'suspicious')) {
    const tgt = vtData._target || '';
    let pattern = '';
    if      (vtData.type === 'ip')     pattern = `[ipv4-addr:value = '${tgt}']`;
    else if (vtData.type === 'domain') pattern = `[domain-name:value = '${tgt}']`;
    else if (vtData.type === 'hash')   pattern = `[file:hashes.'SHA-256' = '${tgt}']`;
    else if (vtData.type === 'url')    pattern = `[url:value = '${tgt}']`;
    if (pattern) {
      addObj({
        type: 'indicator', spec_version: '2.1', id: `indicator--${_uuid4()}`,
        name: `VT — ${tgt}`,
        description: `VirusTotal verdict: ${vtData.verdict}. ${vtData.stats?.malicious||0} malicious / ${vtData.stats?.suspicious||0} suspicious out of ${vtData.total_engines||0} engines.`,
        indicator_types: vtData.verdict === 'malicious' ? ['malicious-activity'] : ['anomalous-activity'],
        pattern, pattern_type: 'stix', valid_from: now, created: now, modified: now,
        labels: ['threat-intelligence'],
      });
    }
  }

  // Report SDO — omit external_references if empty (STIX 2.1 prohibits empty arrays)
  const reportObj = {
    type: 'report', spec_version: '2.1', id: `report--${_uuid4()}`,
    name: scope.caseName || 'OSINT Engagement Report',
    description: [
      `Client: ${scope.client || '—'}`,
      `Scope: ${(scope.domains||[]).join(', ') || '—'}`,
      `IP ranges: ${(scope.ipRanges||[]).join(', ') || '—'}`,
      `Scan type: ${scope.scanType === 'passive' ? 'Passive only' : 'Active allowed'}`,
      `Expiry: ${scope.expiry || '—'}`,
      `Responsible: ${scope.responsable || '—'}`,
    ].join(' | '),
    published: now, created: now, modified: now,
    object_refs: reportRefs,
    labels: ['threat-report'],
  };

  const bundle = {
    type: 'bundle',
    id: `bundle--${_uuid4()}`,
    spec_version: '2.1',
    objects: [reportObj, ...objects],
  };

  _stixValidateAndDownload(bundle, scope.caseName);
}

function _stixValidateAndDownload(bundle, caseName) {
  const filename = `${(caseName || 'aletheia').replace(/[^a-z0-9\-_]/gi, '_')}-stix21.json`;

  // Show a validation modal immediately
  let modal = document.getElementById('stix-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'stix-modal';
    modal.style.cssText = `
      position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:9999;
      display:flex;align-items:center;justify-content:center;
    `;
    modal.innerHTML = `
      <div style="background:#1a1f2e;border:1px solid #2d3347;border-radius:12px;padding:28px 32px;min-width:420px;max-width:600px;width:90%;">
        <div style="font-size:1rem;font-weight:600;color:#c9d1e8;margin-bottom:16px;display:flex;gap:10px;align-items:center;">
          <span id="stix-modal-icon">⏳</span>
          <span id="stix-modal-title">Validando bundle STIX 2.1…</span>
        </div>
        <div id="stix-modal-body" style="font-size:.85rem;color:#8b95b0;line-height:1.6;max-height:280px;overflow-y:auto;"></div>
        <div id="stix-modal-actions" style="display:flex;gap:10px;margin-top:20px;justify-content:flex-end;"></div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  const icon    = document.getElementById('stix-modal-icon');
  const title   = document.getElementById('stix-modal-title');
  const body    = document.getElementById('stix-modal-body');
  const actions = document.getElementById('stix-modal-actions');

  icon.textContent    = '⏳';
  title.textContent   = 'Validando bundle STIX 2.1…';
  body.textContent    = '';
  actions.innerHTML   = '';
  modal.style.display = 'flex';

  function closeModal() { modal.style.display = 'none'; }

  function doDownload() {
    const json = JSON.stringify(bundle, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    closeModal();
  }

  fetch('/api/validate-stix', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(bundle),
  })
  .then(r => r.json())
  .then(res => {
    const count = res.object_count ?? bundle.objects.length;

    if (res.valid) {
      icon.textContent  = '✅';
      title.textContent = 'Bundle STIX 2.1 válido';

      let html = `<div style="color:#4ade80;margin-bottom:8px;">El bundle cumple la especificación STIX 2.1.</div>`;
      html += `<div style="color:#8b95b0;">Objetos incluidos: <strong style="color:#c9d1e8;">${count}</strong></div>`;

      if (res.warnings.length) {
        html += `<div style="margin-top:12px;color:#facc15;font-weight:600;">Advertencias (${res.warnings.length}):</div>`;
        html += `<ul style="margin:6px 0 0 16px;color:#facc15;">` +
          res.warnings.map(w => `<li>${w}</li>`).join('') + `</ul>`;
      }
      body.innerHTML = html;

      const mispBtn = document.createElement('button');
      mispBtn.className = 'secondary-btn';
      mispBtn.textContent = '🔗 Push a MISP';
      mispBtn.onclick = () => _pushToMISP(bundle, body, actions, mispBtn, closeModal);

      const dlBtn = document.createElement('button');
      dlBtn.className = 'run-btn';
      dlBtn.textContent = '⬇ Descargar';
      dlBtn.onclick = doDownload;

      const cancelBtn = document.createElement('button');
      cancelBtn.className = 'secondary-btn';
      cancelBtn.textContent = 'Cerrar';
      cancelBtn.onclick = closeModal;

      actions.appendChild(cancelBtn);
      actions.appendChild(mispBtn);
      actions.appendChild(dlBtn);

    } else {
      icon.textContent  = '❌';
      title.textContent = 'Bundle inválido — errores STIX 2.1';

      let html = `<div style="color:#f87171;margin-bottom:10px;">El bundle no supera la validación. Corrígelo antes de exportar.</div>`;
      html += `<ul style="margin:0 0 0 16px;color:#f87171;">` +
        res.errors.map(e => `<li style="margin-bottom:4px;">${e}</li>`).join('') + `</ul>`;

      if (res.warnings.length) {
        html += `<div style="margin-top:12px;color:#facc15;font-weight:600;">Advertencias:</div>`;
        html += `<ul style="margin:6px 0 0 16px;color:#facc15;">` +
          res.warnings.map(w => `<li>${w}</li>`).join('') + `</ul>`;
      }
      body.innerHTML = html;

      const forceBtn = document.createElement('button');
      forceBtn.className = 'secondary-btn';
      forceBtn.textContent = '⬇ Descargar igualmente';
      forceBtn.onclick = doDownload;

      const cancelBtn = document.createElement('button');
      cancelBtn.className = 'run-btn';
      cancelBtn.textContent = 'Cerrar';
      cancelBtn.onclick = closeModal;

      actions.appendChild(forceBtn);
      actions.appendChild(cancelBtn);
    }
  })
  .catch(() => {
    icon.textContent  = '⚠️';
    title.textContent = 'No se pudo contactar el validador';
    body.innerHTML    = `<div style="color:#facc15;">El backend no respondió. ¿Quieres descargar el bundle sin validar?</div>`;

    const dlBtn = document.createElement('button');
    dlBtn.className = 'run-btn';
    dlBtn.textContent = '⬇ Descargar sin validar';
    dlBtn.onclick = doDownload;

    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'secondary-btn';
    cancelBtn.textContent = 'Cancelar';
    cancelBtn.onclick = closeModal;

    actions.appendChild(cancelBtn);
    actions.appendChild(dlBtn);
  });
}

/* ── Push STIX bundle a MISP ─────────────────────────────────────────────── */

function _pushToMISP(bundle, body, actions, mispBtn, closeModal) {
  mispBtn.disabled = true;
  mispBtn.textContent = '⏳ Enviando…';

  fetch('/api/misp/push', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(bundle),
  })
  .then(r => r.json())
  .then(res => {
    if (res.ok) {
      let html = body.innerHTML;
      html += `<div style="margin-top:14px;padding:12px;background:#0f2a1a;border:1px solid #4ade80;border-radius:8px;">`;
      html += `<div style="color:#4ade80;font-weight:600;margin-bottom:6px;">✅ Evento creado en MISP</div>`;
      if (res.attr_count !== undefined) {
        html += `<div style="color:#8b95b0;font-size:.82rem;margin-bottom:4px;">${res.attr_count} atributos importados</div>`;
      }
      if (res.tags && res.tags.length) {
        html += `<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:6px;">` +
          res.tags.map(t => `<span style="background:#1e3a5f;color:#60a5fa;border-radius:4px;padding:2px 8px;font-size:.78rem;">${t}</span>`).join('') +
          `</div>`;
      }
      if (res.events && res.events.length) {
        html += res.events.map(e =>
          `<a href="${e.url}" target="_blank" rel="noopener"
             style="display:block;color:#60a5fa;font-size:.82rem;margin-top:4px;word-break:break-all;">
             Evento #${e.id} → ${e.url}
           </a>`
        ).join('');
      } else {
        html += `<div style="color:#8b95b0;font-size:.82rem;">Creado correctamente (sin ID devuelto).</div>`;
      }
      html += `</div>`;
      body.innerHTML = html;
      mispBtn.textContent = '✅ Enviado';
    } else {
      let html = body.innerHTML;
      html += `<div style="margin-top:14px;padding:12px;background:#2a0f0f;border:1px solid #f87171;border-radius:8px;">`;
      html += `<div style="color:#f87171;font-weight:600;margin-bottom:4px;">❌ Error al enviar a MISP</div>`;
      html += `<div style="color:#f87171;font-size:.82rem;">${res.error || 'Error desconocido'}</div>`;
      html += `</div>`;
      body.innerHTML = html;
      mispBtn.disabled = false;
      mispBtn.textContent = '🔗 Reintentar';
    }
  })
  .catch(() => {
    let html = body.innerHTML;
    html += `<div style="margin-top:14px;color:#facc15;font-size:.82rem;">No se pudo contactar el backend — ¿está Flask arriba?</div>`;
    body.innerHTML = html;
    mispBtn.disabled = false;
    mispBtn.textContent = '🔗 Reintentar';
  });
}

/* ── Home — actividad reciente ────────────────────────────────────────────── */

function updateHomeActivity() {
  const entries = toolList.map(t => {
    try {
      const raw = sessionStorage.getItem(_histKey(t));
      return raw ? { ...JSON.parse(raw), tool: t } : null;
    } catch(_) { return null; }
  }).filter(Boolean).sort((a, b) => b.timestamp.localeCompare(a.timestamp));

  const lastEl = $('home-last-action');
  if (lastEl && entries.length) {
    const e = entries[0];
    lastEl.textContent = `${toolMeta[e.tool]?.title || e.tool} · ${e.target || '—'} · ${e.timestamp}`;
  }

  const histEl = $('home-activity-list');
  if (!histEl) return;
  if (!entries.length) {
    histEl.innerHTML = '<p class="ui-message">Sin ejecuciones en esta sesión.</p>';
    return;
  }
  histEl.innerHTML = entries.map(e =>
    `<div class="home-act-row" onclick="show('${e.tool}',null)">
      <span class="home-act-tool">${toolMeta[e.tool]?.title || e.tool}</span>
      <span class="home-act-target">${escHtml(e.target || '—')}</span>
      <span class="home-act-time">${e.timestamp}</span>
      <span class="home-act-elapsed">${e.elapsed || ''}</span>
    </div>`
  ).join('');

  // Update tool count
  const toolCountEl = $('home-stat-tools');
  if (toolCountEl) toolCountEl.textContent = toolList.length;
  const cmdCountEl = $('home-stat-cmds');
  if (cmdCountEl) cmdCountEl.textContent = Object.values(SUBTOOLS).reduce((a, v) => a + v.length, 0) + '+';
}

buildToolPanels();
updateHomeActivity();
buildParallelGrid();
_buildParallelProfilesBar();
updateParallelCount();
renderScopeStatus();
const _homeDash = { loaded: false };
loadHomeDashboard();

/* ═══════════════════════════════════════════════
   CYBERNEWS MODULE
═══════════════════════════════════════════════ */

const _news = {
  all: [],
  region: 'all',
  query: '',
  category: 'all',
  loaded: false,
};

const CAT_LABELS = {
  vulnerability: 'Vulnerabilidad',
  malware: 'Malware',
  phishing: 'Phishing',
  breach: 'Brecha',
  apt: 'APT',
  compliance: 'Compliance',
  tools: 'Herramientas',
  general: 'General',
};

function fmtNewsDate(dateStr) {
  if (!dateStr) return '';
  const d = new Date(dateStr);
  if (isNaN(d)) return '';
  const now = new Date();
  const diffH = Math.floor((now - d) / 3600000);
  if (diffH < 1) return 'hace menos de 1h';
  if (diffH < 24) return `hace ${diffH}h`;
  const diffD = Math.floor(diffH / 24);
  if (diffD < 7) return `hace ${diffD}d`;
  return d.toLocaleDateString('es-ES', { day: '2-digit', month: 'short' });
}

function renderNewsCards() {
  const grid = document.getElementById('news-grid');
  const empty = document.getElementById('news-empty');
  const status = document.getElementById('news-status');
  if (!grid) return;

  let items = _news.all;
  if (_news.region !== 'all') items = items.filter(n => n.region === _news.region);
  if (_news.category !== 'all') items = items.filter(n => n.category === _news.category);
  if (_news.query) {
    const q = _news.query;
    items = items.filter(n =>
      n.title.toLowerCase().includes(q) ||
      n.description.toLowerCase().includes(q) ||
      n.source.toLowerCase().includes(q)
    );
  }

  if (status) {
    status.style.display = 'block';
    status.textContent = `${items.length} noticias · ${_news.all.length} total`;
  }

  if (items.length === 0) {
    grid.innerHTML = '';
    if (empty) empty.style.display = 'flex';
    return;
  }
  if (empty) empty.style.display = 'none';

  grid.innerHTML = items.map(n => {
    const regionClass = `news-region-${n.region}`;
    const catClass = `news-cat-${n.category}`;
    const catLabel = CAT_LABELS[n.category] || n.category;
    const date = fmtNewsDate(n.date);
    const desc = n.description ? n.description.substring(0, 200) : '';
    return `<a class="news-card" href="${n.link}" target="_blank" rel="noopener noreferrer">
      <div class="news-card-meta">
        <span class="news-region-dot ${regionClass}"></span>
        <span class="news-card-source">${n.source}</span>
        <span class="news-card-date">${date}</span>
      </div>
      <div class="news-card-title">${n.title}</div>
      ${desc ? `<div class="news-card-desc">${desc}</div>` : ''}
      <span class="news-cat-badge ${catClass}">${catLabel}</span>
    </a>`;
  }).join('');
}

async function loadNews() {
  const loading = document.getElementById('news-loading');
  const grid = document.getElementById('news-grid');
  const btn = document.getElementById('news-refresh-btn');
  const status = document.getElementById('news-status');

  if (loading) loading.style.display = 'flex';
  if (grid) grid.innerHTML = '';
  if (btn) btn.disabled = true;
  if (status) status.style.display = 'none';

  try {
    const res = await fetch('/api/news');
    const data = await res.json();
    _news.all = data.news || [];
    _news.loaded = true;
    renderNewsCards();
  } catch (e) {
    if (grid) grid.innerHTML = '<div style="color:var(--red);padding:20px 0;font-size:.85rem;">⚠️ Error al cargar noticias. Comprueba la conexión.</div>';
  } finally {
    if (loading) loading.style.display = 'none';
    if (btn) btn.disabled = false;
  }
}

function setNewsRegion(region, el) {
  _news.region = region;
  document.querySelectorAll('.news-filter-btn').forEach(b => b.classList.remove('active'));
  if (el) el.classList.add('active');
  renderNewsCards();
}

function onNewsSearch(val) {
  _news.query = val.trim().toLowerCase();
  renderNewsCards();
}

function onNewsCat(val) {
  _news.category = val;
  renderNewsCards();
}

let _orgsLoaded = false;
function _loadScopeOrgs() {
  if (_orgsLoaded) return;
  const sel = document.getElementById('scope-org');
  if (!sel) return;
  fetch('/admin/orgs/list')
    .then(r => r.json())
    .then(orgs => {
      if (!Array.isArray(orgs)) return;
      const saved = (getScope() || {}).org_id || '';
      orgs.forEach(o => {
        const opt = document.createElement('option');
        opt.value = o.id;
        opt.textContent = o.nombre;
        if (String(o.id) === String(saved)) opt.selected = true;
        sel.appendChild(opt);
      });
      _orgsLoaded = true;
    })
    .catch(() => {});
}

const _origShow = show;
window.show = function (panel, btn) {
  _origShow(panel, btn);
  if (panel === 'home' && !_homeDash.loaded) loadHomeDashboard();
  if (panel === 'overview' && !_overview.loaded) loadOverview();
  if (panel === 'news' && !_news.loaded) loadNews();
  if (panel === 'cves' && !_cves.loaded) loadCVEs();
  if (panel === 'iocs' && !_iocs.loaded) loadIOCs();
  if (panel === 'sources' && !_sources.loaded) loadSources();
  if (panel === 'scope') _loadScopeOrgs();
  if (panel === 'exposure') {
    const topTarget = (document.getElementById('targetInput') || {}).value || '';
    const inp = document.getElementById('exp-target-input');
    if (inp && !inp.value && topTarget) inp.value = topTarget;
    const emptyEl = document.getElementById('exp-empty');
    if (emptyEl && !document.getElementById('exp-ip-grid').innerHTML) emptyEl.style.display = 'flex';
  }
  if (panel === 'breaches') {
    const emptyEl = document.getElementById('harvest-empty');
    const results = document.getElementById('harvest-results');
    if (emptyEl && results && results.style.display === 'none') emptyEl.style.display = 'flex';
  }
};

/* ═══════════════════════════════════════════════
   OVERVIEW MODULE
═══════════════════════════════════════════════ */

const _overview = { loaded: false };

function _setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function renderOverview(d) {
  const risk = d.risk || {};
  const kev  = d.kev  || {};
  const iocs = d.iocs || {};
  const news = d.news || {};

  // Risk card
  const riskCard = document.getElementById('ov-risk-card');
  if (riskCard) {
    riskCard.className = `ov-risk-card ov-risk-${risk.level || 'BAJO'}`;
  }
  _setEl('ov-risk-score', risk.score ?? '—');
  _setEl('ov-risk-level', risk.level ?? '—');

  // KPIs
  _setEl('ov-kev-total', (kev.total ?? '—').toLocaleString?.() ?? kev.total);
  _setEl('ov-kev-7d', `${kev.new_7d ?? 0} nuevos esta semana`);
  _setEl('ov-ioc-total', (iocs.total ?? '—').toLocaleString?.() ?? iocs.total);
  _setEl('ov-ransom-total', kev.ransomware_count ?? '—');
  _setEl('ov-news-total', news.count ?? '—');

  // Recent KEV list
  const kevList = document.getElementById('ov-kev-list');
  if (kevList) {
    kevList.innerHTML = (d.recent_kev || []).map(c => `
      <div class="ov-kev-item">
        <span class="ov-kev-id">${c.id}</span>
        <span class="ov-kev-product">${[c.vendor, c.product].filter(Boolean).join(' · ')}</span>
        ${c.ransomware ? '<span class="ov-kev-ransom">⚠ Ransom</span>' : ''}
        <span class="ov-kev-date">${c.date}</span>
      </div>`).join('') || '<div style="color:var(--text3);font-size:.78rem">Sin datos</div>';
  }

  // Recent IOCs list
  const iocList = document.getElementById('ov-ioc-list');
  if (iocList) {
    iocList.innerHTML = (d.recent_iocs || []).map(i => `
      <div class="ov-ioc-item">
        <span class="ioc-type-badge ioc-type-${i.indicator?.includes('http') ? 'url' : 'ip'}">${i.indicator?.includes('http') ? 'URL' : 'IP'}</span>
        <span class="ov-ioc-indicator">${i.indicator || '—'}</span>
        <span class="ov-ioc-threat">${i.threat || ''}</span>
      </div>`).join('') || '<div style="color:var(--text3);font-size:.78rem">Sin datos</div>';
  }

  // Source status
  const sourcesList = document.getElementById('ov-sources-list');
  if (sourcesList) {
    sourcesList.innerHTML = Object.entries(d.sources || {}).map(([name, ok]) => `
      <div class="ov-source-row">
        <span class="ov-source-dot ${ok ? 'ok' : 'err'}"></span>
        <span class="ov-source-name">${name}</span>
        <span class="ov-source-status ${ok ? 'ok' : 'err'}">${ok ? 'ONLINE' : 'ERROR'}</span>
      </div>`).join('');
  }

  // IOC breakdown bars
  const breakdown = document.getElementById('ov-ioc-breakdown');
  if (breakdown && iocs.total > 0) {
    const bars = [
      { label: 'URLs (URLhaus)', val: iocs.urlhaus || 0, color: '#3498db' },
      { label: 'Hashes (Bazaar)', val: iocs.bazaar || 0, color: '#9b59b6' },
      { label: 'IPs C2 (Feodo)', val: iocs.feodo || 0, color: '#e74c3c' },
    ];
    const max = Math.max(...bars.map(b => b.val), 1);
    breakdown.innerHTML = bars.map(b => `
      <div class="ov-breakdown-row">
        <span class="ov-breakdown-label">${b.label}</span>
        <div class="ov-breakdown-bar-wrap">
          <div class="ov-breakdown-bar" style="width:${Math.round(b.val/max*100)}%;background:${b.color}"></div>
        </div>
        <span class="ov-breakdown-val">${b.val}</span>
      </div>`).join('');
  }

  // Recent news
  const newsList = document.getElementById('ov-news-list');
  if (newsList) {
    newsList.innerHTML = (d.recent_news || []).map(n => `
      <div class="ov-news-item">
        <div class="ov-news-title">${n.title || '—'}</div>
        <div class="ov-news-meta">${n.source || ''} · ${n.date ? new Date(n.date).toLocaleDateString('es-ES') : ''}</div>
      </div>`).join('') || '<div style="color:var(--text3);font-size:.78rem">Sin datos</div>';
  }

  // Show sections
  const kpiRow = document.getElementById('ov-kpi-row');
  const mainGrid = document.getElementById('ov-main-grid');
  if (kpiRow) kpiRow.style.display = 'grid';
  if (mainGrid) mainGrid.style.display = 'grid';
}

async function loadOverview() {
  const loading = document.getElementById('overview-loading');
  const btn = document.getElementById('overview-refresh-btn');
  const kpiRow = document.getElementById('ov-kpi-row');
  const mainGrid = document.getElementById('ov-main-grid');

  if (loading) loading.style.display = 'flex';
  if (kpiRow) kpiRow.style.display = 'none';
  if (mainGrid) mainGrid.style.display = 'none';
  if (btn) btn.disabled = true;

  try {
    const res = await fetch('/api/overview');
    const data = await res.json();
    _overview.loaded = true;
    renderOverview(data);
  } catch (e) {
    const mainGrid = document.getElementById('ov-main-grid');
    if (mainGrid) {
      mainGrid.style.display = 'block';
      mainGrid.innerHTML = `<div style="color:var(--red);padding:20px;font-size:.85rem">⚠️ Error: ${escHtml(String(e))}</div>`;
    }
    console.error('loadOverview error:', e);
  } finally {
    if (loading) loading.style.display = 'none';
    if (btn) btn.disabled = false;
  }
}

/* ═══════════════════════════════════════════════
   HOME DASHBOARD
═══════════════════════════════════════════════ */

async function loadHomeDashboard() {
  if (_homeDash.loaded) return;
  const hnLoading = $('home-news-loading');
  const hovLoading = $('home-ov-loading');
  if (hnLoading) hnLoading.style.display = 'flex';
  if (hovLoading) hovLoading.style.display = 'flex';

  try {
    const [newsRes, ovRes] = await Promise.all([
      fetch('/api/news'),
      fetch('/api/overview'),
    ]);
    const newsData = await newsRes.json();
    const ovData = await ovRes.json();

    const articles = (newsData.news || []).slice(0, 3);
    const mini = $('home-news-mini');
    if (mini) {
      mini.innerHTML = articles.map(n => {
        const date = fmtNewsDate ? fmtNewsDate(n.date) : '';
        const catLabel = (CAT_LABELS && CAT_LABELS[n.category]) || n.category || 'General';
        const desc = n.description ? n.description.substring(0, 160) : '';
        return `<a class="news-card" href="${escHtml(n.link || '#')}" target="_blank" rel="noopener noreferrer">
          <div class="news-card-meta">
            <span class="news-region-dot news-region-${n.region}"></span>
            <span class="news-card-source">${escHtml(n.source || '')}</span>
            <span class="news-card-date">${date}</span>
          </div>
          <div class="news-card-title">${escHtml(n.title || '')}</div>
          ${desc ? `<div class="news-card-desc">${escHtml(desc)}</div>` : ''}
          <span class="news-cat-badge news-cat-${n.category}">${escHtml(catLabel)}</span>
        </a>`;
      }).join('') || '<div style="color:var(--text3);font-size:.82rem;padding:8px 0">Sin noticias disponibles</div>';
    }

    const d = ovData;
    const risk = d.risk || {};
    const kev  = d.kev  || {};
    const iocs = d.iocs || {};
    const news = d.news || {};

    const kevList = $('home-kev-list');
    if (kevList) {
      kevList.innerHTML = (d.recent_kev || []).map(c => `
        <div class="ov-kev-item">
          <span class="ov-kev-id">${escHtml(c.id)}</span>
          <span class="ov-kev-product">${escHtml([c.vendor, c.product].filter(Boolean).join(' · '))}</span>
          ${c.ransomware ? '<span class="ov-kev-ransom">⚠ Ransom</span>' : ''}
          <span class="ov-kev-date">${escHtml(c.date || '')}</span>
        </div>`).join('') || '<div style="color:var(--text3);font-size:.78rem">Sin datos</div>';
    }

    const iocList = $('home-ioc-list');
    if (iocList) {
      iocList.innerHTML = (d.recent_iocs || []).map(i => `
        <div class="ov-ioc-item">
          <span class="ioc-type-badge ioc-type-${i.indicator?.includes('http') ? 'url' : 'ip'}">${i.indicator?.includes('http') ? 'URL' : 'IP'}</span>
          <span class="ov-ioc-indicator">${escHtml(i.indicator || '—')}</span>
          <span class="ov-ioc-threat">${escHtml(i.threat || '')}</span>
        </div>`).join('') || '<div style="color:var(--text3);font-size:.78rem">Sin datos</div>';
    }

    const tables = $('home-ov-tables');
    if (tables) tables.style.display = 'grid';

    const kpiRow = $('home-kpi-row');
    if (kpiRow) {
      _setEl('hkv-risk', risk.score ?? '—');
      _setEl('hkv-risk-level', risk.level ?? '—');
      _setEl('hkv-kev', (kev.total ?? '—').toLocaleString?.() ?? kev.total);
      _setEl('hkv-kev-sub', `${kev.new_7d ?? 0} nuevos esta semana`);
      _setEl('hkv-ioc', (iocs.total ?? '—').toLocaleString?.() ?? iocs.total);
      _setEl('hkv-ransom', kev.ransomware_count ?? '—');
      _setEl('hkv-news', news.count ?? '—');
      const riskCard = $('home-kpi-risk-card');
      if (riskCard) riskCard.className = `home-kpi-card home-kpi-risk ov-risk-${risk.level || 'BAJO'}`;
      kpiRow.style.display = 'grid';
    }

    _homeDash.loaded = true;
  } catch(e) {
    console.error('loadHomeDashboard error:', e);
  } finally {
    if (hnLoading) hnLoading.style.display = 'none';
    if (hovLoading) hovLoading.style.display = 'none';
  }
}

/* ═══════════════════════════════════════════════
   CVEs MODULE
═══════════════════════════════════════════════ */

const _cves = { all: [], sev: 'all', query: '', loaded: false };

function renderCVEs() {
  const grid = document.getElementById('cves-grid');
  const empty = document.getElementById('cves-empty');
  if (!grid) return;

  let items = _cves.all;
  if (_cves.sev === 'exploited') items = items.filter(c => c.actively_exploited);
  else if (_cves.sev === 'CRITICAL') items = items.filter(c => c.severity === 'CRITICAL');
  else if (_cves.sev === 'HIGH') items = items.filter(c => c.severity === 'HIGH');
  if (_cves.query) {
    const q = _cves.query;
    items = items.filter(c =>
      c.id.toLowerCase().includes(q) ||
      c.description.toLowerCase().includes(q) ||
      c.vendor.toLowerCase().includes(q) ||
      c.product.toLowerCase().includes(q)
    );
  }

  if (items.length === 0) {
    grid.innerHTML = '';
    if (empty) empty.style.display = 'flex';
    return;
  }
  if (empty) empty.style.display = 'none';

  grid.innerHTML = items.map(c => {
    const score = c.score != null ? c.score.toFixed(1) : '—';
    const sev = c.severity || 'UNKNOWN';
    const exploitedBadge = c.actively_exploited
      ? '<span class="cve-badge cve-badge-kev">🔴 CISA KEV</span>' : '';
    const ransomBadge = c.ransomware && c.ransomware !== 'Unknown'
      ? '<span class="cve-badge cve-badge-ransom">⚠ Ransomware</span>' : '';
    const dateBadge = c.kev_date_added || c.published
      ? `<span class="cve-badge cve-badge-date">${c.kev_date_added || c.published}</span>` : '';
    const product = [c.vendor, c.product].filter(Boolean).join(' · ');

    return `<div class="cve-card ${c.actively_exploited ? 'cve-exploited' : ''}">
      <div class="cve-score-badge sev-${sev}">
        <span class="cve-score-num">${score}</span>
        <span class="cve-score-sev">${sev}</span>
      </div>
      <div class="cve-body">
        <div class="cve-header">
          <a class="cve-id cve-id-link" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.id)}" target="_blank" rel="noopener">${c.id} ↗</a>
          ${product ? `<span class="cve-product">${product}</span>` : ''}
        </div>
        <div class="cve-desc">${c.description || 'Sin descripción disponible.'}</div>
      </div>
      <div class="cve-badges">
        ${exploitedBadge}
        ${ransomBadge}
        ${dateBadge}
      </div>
    </div>`;
  }).join('');
}

async function loadCVEs() {
  const loading = document.getElementById('cves-loading');
  const grid = document.getElementById('cves-grid');
  const btn = document.getElementById('cves-refresh-btn');
  const stats = document.getElementById('cves-stats');

  if (loading) loading.style.display = 'flex';
  if (grid) grid.innerHTML = '';
  if (btn) btn.disabled = true;
  if (stats) stats.style.display = 'none';

  try {
    const res = await fetch('/api/cves');
    const data = await res.json();
    _cves.all = data.cves || [];
    _cves.loaded = true;

    const exploited = _cves.all.filter(c => c.actively_exploited).length;
    const ransom = _cves.all.filter(c => c.ransomware && c.ransomware !== 'Unknown').length;
    const setEl = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    setEl('cves-stat-total', _cves.all.length);
    setEl('cves-stat-kev', exploited);
    setEl('cves-stat-ransom', ransom);
    if (stats) stats.style.display = 'grid';

    renderCVEs();
  } catch (e) {
    if (grid) grid.innerHTML = '<div style="color:var(--red);padding:20px 0;font-size:.85rem;">⚠️ Error al cargar CVEs.</div>';
  } finally {
    if (loading) loading.style.display = 'none';
    if (btn) btn.disabled = false;
  }
}

function setCVESev(sev, el) {
  _cves.sev = sev;
  document.querySelectorAll('[data-sev]').forEach(b => b.classList.remove('active'));
  if (el) el.classList.add('active');
  renderCVEs();
}

function onCVESearch(val) {
  _cves.query = val.trim().toLowerCase();
  renderCVEs();
}

/* ═══════════════════════════════════════════════
   IOCs MODULE
═══════════════════════════════════════════════ */

const _iocs = { all: [], itype: 'all', query: '', loaded: false };

function fmtIOCDate(d) {
  if (!d) return '—';
  const parsed = new Date(d);
  if (isNaN(parsed)) return d.substring(0, 10);
  return parsed.toLocaleDateString('es-ES', { day: '2-digit', month: 'short', year: '2-digit' });
}

function renderIOCs() {
  const tbody = document.getElementById('iocs-tbody');
  const empty = document.getElementById('iocs-empty');
  const wrap = document.getElementById('iocs-table-wrap');
  if (!tbody) return;

  let items = _iocs.all;
  if (_iocs.itype !== 'all') items = items.filter(i => i.type === _iocs.itype);
  if (_iocs.query) {
    const q = _iocs.query;
    items = items.filter(i =>
      i.indicator.toLowerCase().includes(q) ||
      (i.threat || '').toLowerCase().includes(q) ||
      (i.tags || []).some(t => t.toLowerCase().includes(q))
    );
  }

  if (items.length === 0) {
    tbody.innerHTML = '';
    if (wrap) wrap.style.display = 'none';
    if (empty) empty.style.display = 'flex';
    return;
  }
  if (wrap) wrap.style.display = 'block';
  if (empty) empty.style.display = 'none';

  tbody.innerHTML = items.slice(0, 200).map(i => {
    const tags = (i.tags || []).slice(0, 4).map(t => `<span class="ioc-tag">${t}</span>`).join('');
    return `<tr>
      <td><span class="ioc-type-badge ioc-type-${i.type}">${i.type.toUpperCase()}</span></td>
      <td><span class="ioc-indicator">${i.indicator}</span></td>
      <td style="color:var(--text);font-size:.75rem">${i.threat || '—'}</td>
      <td><div class="ioc-tags">${tags || '—'}</div></td>
      <td style="white-space:nowrap;font-size:.72rem">${fmtIOCDate(i.date)}</td>
      <td><span class="ioc-source">${i.source}</span></td>
    </tr>`;
  }).join('');
}

async function loadIOCs() {
  const loading = document.getElementById('iocs-loading');
  const btn = document.getElementById('iocs-refresh-btn');
  const stats = document.getElementById('iocs-stats');
  const wrap = document.getElementById('iocs-table-wrap');

  if (loading) loading.style.display = 'flex';
  if (wrap) wrap.style.display = 'none';
  if (btn) btn.disabled = true;
  if (stats) stats.style.display = 'none';

  try {
    const res = await fetch('/api/iocs');
    const data = await res.json();
    _iocs.all = data.iocs || [];
    _iocs.loaded = true;

    const urls = _iocs.all.filter(i => i.type === 'url').length;
    const ips = _iocs.all.filter(i => i.type === 'ip').length;
    const hashes = _iocs.all.filter(i => i.type === 'hash').length;
    const setEl = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    setEl('iocs-stat-total', _iocs.all.length);
    setEl('iocs-stat-urls', urls);
    setEl('iocs-stat-ips', ips);
    setEl('iocs-stat-hashes', hashes);
    if (stats) stats.style.display = 'grid';

    renderIOCs();
  } catch (e) {
    const tbody = document.getElementById('iocs-tbody');
    if (tbody) tbody.innerHTML = '<tr><td colspan="6" style="color:var(--red);padding:20px">⚠️ Error al cargar IOCs.</td></tr>';
    if (wrap) wrap.style.display = 'block';
  } finally {
    if (loading) loading.style.display = 'none';
    if (btn) btn.disabled = false;
  }
}

function setIOCType(itype, el) {
  _iocs.itype = itype;
  document.querySelectorAll('[data-itype]').forEach(b => b.classList.remove('active'));
  if (el) el.classList.add('active');
  renderIOCs();
}

function onIOCSearch(val) {
  _iocs.query = val.trim().toLowerCase();
  renderIOCs();
}

/* ═══════════════════════════════════════════════
   SOURCES MODULE
═══════════════════════════════════════════════ */

const _sources = { all: [], cat: 'all', loaded: false };

const _SRC_CAT_COLORS = {
  'CVE':  { bg: 'rgba(255,140,0,0.15)',   color: '#ff8c00' },
  'IOC':  { bg: 'rgba(231,76,60,0.15)',   color: '#e74c3c' },
  'News': { bg: 'rgba(41,128,185,0.15)',  color: '#3498db' },
};

function setSrcCat(cat, el) {
  _sources.cat = cat;
  document.querySelectorAll('[data-scat]').forEach(b => b.classList.remove('active'));
  if (el) el.classList.add('active');
  renderSources();
}

function renderSources() {
  const grid = document.getElementById('src-grid');
  if (!grid) return;

  let items = _sources.all;
  if (_sources.cat !== 'all') items = items.filter(s => s.category === _sources.cat);

  if (!items.length) {
    grid.innerHTML = '<div style="color:var(--text3);padding:40px 0;text-align:center;font-size:.85rem">Sin fuentes para mostrar.</div>';
    return;
  }

  grid.innerHTML = items.map(s => {
    const cat = _SRC_CAT_COLORS[s.category] || { bg: 'rgba(173,198,255,0.1)', color: 'var(--accent)' };
    const msClass = s.response_ms < 500 ? 'ms-fast' : s.response_ms < 2000 ? 'ms-ok' : 'ms-slow';
    const statusLabel = s.ok
      ? 'ONLINE'
      : (s.error || (s.status_code ? 'HTTP ' + s.status_code : 'ERROR'));
    return `<div class="src-card ${s.ok ? 'src-ok' : 'src-err'}">
      <div class="src-card-header">
        <span class="src-status-dot ${s.ok ? 'ok' : 'err'}"></span>
        <span class="src-name">${escHtml(s.name)}</span>
        <span class="src-cat-badge" style="background:${cat.bg};color:${cat.color}">${s.category}</span>
      </div>
      <div class="src-desc">${escHtml(s.description)}</div>
      <div class="src-meta">
        <span class="src-status-label ${s.ok ? 'ok' : 'err'}">${escHtml(statusLabel)}</span>
        ${s.ok ? `<span class="src-ms ${msClass}">${s.response_ms} ms</span>` : ''}
        ${s.status_code && !s.ok ? `<span class="src-code">HTTP ${s.status_code}</span>` : ''}
        ${s.ok && s.status_code ? `<span class="src-code" style="margin-left:auto">HTTP ${s.status_code}</span>` : ''}
      </div>
      <div class="src-url">${escHtml(s.url)}</div>
    </div>`;
  }).join('');
}

async function loadSources() {
  const loading = document.getElementById('sources-loading');
  const grid = document.getElementById('src-grid');
  const btn = document.getElementById('sources-refresh-btn');
  const summary = document.getElementById('src-summary');
  const filters = document.getElementById('src-filters');

  if (loading) loading.style.display = 'flex';
  if (grid) grid.innerHTML = '';
  if (btn) btn.disabled = true;
  if (summary) summary.style.display = 'none';
  if (filters) filters.style.display = 'none';

  try {
    const res = await fetch('/api/sources');
    const data = await res.json();
    _sources.all = data.sources || [];
    _sources.loaded = true;

    const sum = data.summary || {};
    const setEl = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    setEl('src-total',   sum.total ?? '—');
    setEl('src-online',  sum.online ?? '—');
    setEl('src-offline', sum.offline ?? '—');
    setEl('src-avg-ms',  sum.avg_response_ms ?? '—');
    setEl('src-checked-at', data.checked_at
      ? new Date(data.checked_at).toLocaleTimeString('es-ES')
      : '—');

    if (summary) summary.style.display = 'grid';
    if (filters) filters.style.display = 'flex';

    renderSources();
  } catch (e) {
    if (grid) grid.innerHTML = '<div style="color:var(--red);padding:20px;font-size:.85rem">⚠️ Error al comprobar las fuentes. Comprueba la conexión.</div>';
  } finally {
    if (loading) loading.style.display = 'none';
    if (btn) btn.disabled = false;
  }
}

/* ═══════════════════════════════════════════════
   EXPOSURE MODULE  (Shodan InternetDB)
═══════════════════════════════════════════════ */

/* ── Shodan Full ──────────────────────────────────────────────────────────── */

async function searchShodan() {
  const inp = document.getElementById('sh-target-input');
  const tgt = inp ? inp.value.trim() : '';
  if (!tgt) { inp && inp.focus(); return; }

  const loading = $('sh-loading'), error = $('sh-error'),
        summary = $('sh-summary'), empty  = $('sh-empty'),
        btn     = $('sh-search-btn');

  loading.style.display = 'flex';
  error.style.display   = 'none';
  summary.style.display = 'none';
  empty.style.display   = 'none';
  btn.disabled = true;

  try {
    const r = await fetch(`/api/shodan-full?target=${encodeURIComponent(tgt)}`);
    const d = await r.json();

    if (!r.ok || d.error) {
      error.textContent = d.error || 'Error desconocido';
      error.style.display = 'block';
      return;
    }

    // Cache raw data for report generation
    try { sessionStorage.setItem('aletheia_shodan_data', JSON.stringify({ ...d, _target: tgt })); } catch(_) {}

    // Source notice
    const noticeEl = $('sh-source-notice');
    if (d.source === 'internetdb') {
      noticeEl.innerHTML = '<span class="sh-notice-idb">ℹ Plan OSS no permite esta IP — datos básicos vía Shodan InternetDB (sin banners ni SSL)</span>';
      noticeEl.style.display = 'block';
    } else {
      noticeEl.style.display = 'none';
    }

    // Host overview
    setText('sh-ip',      d.ip || '—');
    setText('sh-org',     d.org || '—');
    setText('sh-isp',     d.isp || '—');
    setText('sh-asn',     d.asn || '—');
    setText('sh-os',      d.os || '—');
    setText('sh-updated', d.last_update || '—');
    const loc = [d.city, d.region, d.country].filter(Boolean).join(', ');
    setText('sh-loc', loc || '—');

    const tagsEl = $('sh-tags');
    tagsEl.innerHTML = (d.tags || []).map(t => `<span class="sh-tag">${escHtml(t)}</span>`).join('');

    const hnEl = $('sh-hostnames');
    const allHosts = [...new Set([...(d.hostnames||[]), ...(d.domains||[])])];
    if (allHosts.length) {
      hnEl.textContent = allHosts.join(' · ');
      hnEl.style.display = 'block';
    } else {
      hnEl.style.display = 'none';
    }

    const services = d.services || [];
    const vulns    = d.vulns    || [];

    // Stats
    setText('sh-stat-ports', (d.ports || []).length);
    setText('sh-stat-vulns', vulns.length);
    setText('sh-stat-ssl',   services.filter(s => s.ssl).length);
    setText('sh-stat-http',  services.filter(s => s.http).length);

    // For InternetDB fallback: enrich service stubs with matching CPEs
    const cpes = d.cpes || [];
    if (d.source === 'internetdb' && cpes.length) {
      services.forEach(s => {
        s.cpe = cpes.filter(c => c.includes(`:${s.port}:`) || c.includes(`/${s.port}/`));
      });
    }

    // Services
    const svcEl = $('sh-services-list');
    if (services.length) {
      svcEl.innerHTML = services.map(s => {
        const product = [s.product, s.version].filter(Boolean).join(' ');
        const label   = product || s.module || '';

        // HTTP block
        let httpHtml = '';
        if (s.http) {
          httpHtml = `<div class="sh-svc-block">
            <span class="sh-svc-block-label">HTTP</span>
            <span class="sh-svc-kv"><b>Status</b> ${s.http.status || '—'}</span>
            ${s.http.server ? `<span class="sh-svc-kv"><b>Server</b> ${escHtml(s.http.server)}</span>` : ''}
            ${s.http.title  ? `<span class="sh-svc-kv"><b>Title</b> ${escHtml(s.http.title)}</span>` : ''}
          </div>`;
        }

        // SSL block
        let sslHtml = '';
        if (s.ssl) {
          const cert = s.ssl.cert || {};
          const cipher = s.ssl.cipher || {};
          const versions = (s.ssl.versions || []).join(', ');
          sslHtml = `<div class="sh-svc-block">
            <span class="sh-svc-block-label">SSL/TLS</span>
            ${cert.subject_cn ? `<span class="sh-svc-kv"><b>Subject</b> ${escHtml(cert.subject_cn)}</span>` : ''}
            ${cert.issuer_cn  ? `<span class="sh-svc-kv"><b>Issuer</b> ${escHtml(cert.issuer_cn)}</span>`  : ''}
            ${cert.expires    ? `<span class="sh-svc-kv"><b>Expira</b> ${escHtml(cert.expires)}</span>`    : ''}
            ${cipher.name     ? `<span class="sh-svc-kv"><b>Cipher</b> ${escHtml(cipher.name)} (${cipher.bits || ''}b)</span>` : ''}
            ${versions        ? `<span class="sh-svc-kv"><b>Versiones</b> ${escHtml(versions)}</span>`     : ''}
          </div>`;
        }

        // Banner block
        const bannerHtml = s.banner
          ? `<pre class="sh-banner">${escHtml(s.banner)}</pre>`
          : '';

        // CPEs
        const cpeHtml = s.cpe && s.cpe.length
          ? `<div class="sh-cpe-row">${s.cpe.map(c => `<span class="sh-cpe-chip">${escHtml(c)}</span>`).join('')}</div>`
          : '';

        return `<div class="sh-svc-card">
          <div class="sh-svc-header">
            <span class="sh-svc-port">${s.port}<span class="sh-svc-transport">/${s.transport}</span></span>
            ${label ? `<span class="sh-svc-label">${escHtml(label)}</span>` : ''}
            ${s.ssl ? '<span class="sh-svc-badge sh-badge-ssl">SSL</span>' : ''}
            ${s.http ? '<span class="sh-svc-badge sh-badge-http">HTTP</span>' : ''}
            <span class="sh-svc-date">${s.timestamp || ''}</span>
          </div>
          ${bannerHtml}
          ${httpHtml}
          ${sslHtml}
          ${cpeHtml}
        </div>`;
      }).join('');
    } else {
      svcEl.innerHTML = '<p class="ui-message">Sin datos de servicios.</p>';
    }

    // CVEs
    const vulnsSection = $('sh-vulns-section');
    const vulnsEl      = $('sh-vulns-list');
    if (vulns.length) {
      vulnsSection.style.display = 'block';
      vulnsEl.innerHTML = vulns.map(id =>
        `<div class="sh-vuln-card">
          <span class="sh-vuln-id">${escHtml(id)}</span>
          <a class="sh-vuln-link" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}"
             target="_blank" rel="noopener">NVD ↗</a>
        </div>`
      ).join('');
    } else {
      vulnsSection.style.display = 'none';
    }

    summary.style.display = 'block';
    const expBtn = $('sh-export-btn');
    if (expBtn) expBtn.style.display = '';
  } catch (e) {
    error.textContent = 'Error de conexión: ' + e.message;
    error.style.display = 'block';
  } finally {
    loading.style.display = 'none';
    btn.disabled = false;
  }
}

/* ── VirusTotal ───────────────────────────────────────────────────────────── */

async function searchVT() {
  const inp = document.getElementById('vt-target-input');
  const tgt = inp ? inp.value.trim() : '';
  if (!tgt) { inp && inp.focus(); return; }

  const loading  = $('vt-loading'),  error   = $('vt-error'),
        results  = $('vt-results'),   empty   = $('vt-empty'),
        pending  = $('vt-pending'),   btn     = $('vt-search-btn');

  loading.style.display = 'flex';
  error.style.display   = 'none';
  results.style.display = 'none';
  empty.style.display   = 'none';
  pending.style.display = 'none';
  btn.disabled = true;

  try {
    const r = await fetch(`/api/virustotal?target=${encodeURIComponent(tgt)}`);
    const d = await r.json();

    if (!r.ok || d.error) {
      error.textContent = d.error || 'Error desconocido';
      error.style.display = 'block';
      return;
    }

    // Cache raw data for report generation
    try { sessionStorage.setItem('aletheia_vt_data', JSON.stringify({ ...d, _target: tgt })); } catch(_) {}

    if (d.pending) {
      pending.textContent = d.message;
      pending.style.display = 'block';
      return;
    }

    // Verdict badge
    const badge = $('vt-verdict-badge');
    const verdictLabel = { malicious: 'MALICIOSO', suspicious: 'SOSPECHOSO', clean: 'LIMPIO' };
    badge.textContent = verdictLabel[d.verdict] || d.verdict.toUpperCase();
    badge.className = `vt-verdict-badge vt-verdict-${d.verdict}`;

    // Detection ratio
    const stats = d.stats || {};
    const mal = stats.malicious || 0;
    const sus = stats.suspicious || 0;
    setText('vt-detection-ratio', `${mal + sus} / ${d.total_engines} motores`);
    setText('vt-mal', mal);
    setText('vt-sus', sus);
    setText('vt-ok',  stats.harmless || 0);
    setText('vt-un',  stats.undetected || 0);

    // Meta
    const typeLabel = { ip: 'Dirección IP', domain: 'Dominio', hash: 'Hash de fichero', url: 'URL' };
    setText('vt-type',       typeLabel[d.type] || d.type);
    setText('vt-reputation', d.reputation !== undefined ? d.reputation : '—');
    setText('vt-date',       d.last_analysis_date || '—');

    // Extra metadata (varies by type)
    const extra = [];
    if (d.country)          extra.push(['País', d.country]);
    if (d.as_owner)         extra.push(['AS Owner', d.as_owner]);
    if (d.registrar)        extra.push(['Registrar', d.registrar]);
    if (d.meaningful_name)  extra.push(['Nombre', d.meaningful_name]);
    if (d.type_description) extra.push(['Tipo fichero', d.type_description]);
    if (d.size)             extra.push(['Tamaño', `${(d.size/1024).toFixed(1)} KB`]);
    const extraEl = $('vt-extra-row');
    extraEl.innerHTML = extra.map(([k, v]) =>
      `<div class="vt-extra-item"><span class="vt-meta-label">${escHtml(k)}</span><span>${escHtml(String(v))}</span></div>`
    ).join('');

    // Tags
    const tagsEl = $('vt-tags');
    tagsEl.innerHTML = (d.tags || []).map(t => `<span class="sh-tag">${escHtml(t)}</span>`).join('');

    // Categories
    const cats = d.categories || {};
    const catKeys = Object.values(cats).filter((v, i, a) => a.indexOf(v) === i);
    if (catKeys.length) {
      tagsEl.innerHTML += catKeys.map(c => `<span class="sh-tag" style="background:var(--amber-soft);color:var(--amber)">${escHtml(c)}</span>`).join('');
    }

    // Flagged engines
    const flaggedSection = $('vt-flagged-section');
    const enginesGrid    = $('vt-engines-grid');
    const cleanMsg       = $('vt-clean-msg');
    if (d.flagged && d.flagged.length) {
      flaggedSection.style.display = 'block';
      cleanMsg.style.display = 'none';
      enginesGrid.innerHTML = d.flagged.map(f => {
        const cls = f.category === 'malicious' ? 'vt-engine-mal' : 'vt-engine-sus';
        return `<div class="vt-engine-card ${cls}">
          <span class="vt-engine-name">${escHtml(f.engine)}</span>
          <span class="vt-engine-result">${escHtml(f.result || f.category)}</span>
        </div>`;
      }).join('');
    } else {
      flaggedSection.style.display = 'none';
      cleanMsg.style.display = 'block';
    }

    results.style.display = 'block';
    const expBtn = $('vt-export-btn');
    if (expBtn) expBtn.style.display = '';
  } catch (e) {
    error.textContent = 'Error de conexión: ' + e.message;
    error.style.display = 'block';
  } finally {
    loading.style.display = 'none';
    btn.disabled = false;
  }
}

/* ── Exposure ─────────────────────────────────────────────────────────────── */

async function searchExposure() {
  const inp     = document.getElementById('exp-target-input');
  const target  = inp ? inp.value.trim() : '';
  const loading = document.getElementById('exp-loading');
  const summary = document.getElementById('exp-summary');
  const vulnsRow = document.getElementById('exp-vulns-row');
  const grid    = document.getElementById('exp-ip-grid');
  const emptyEl = document.getElementById('exp-empty');
  const errEl   = document.getElementById('exp-error');
  const btn     = document.getElementById('exp-search-btn');

  if (!target) { if (inp) inp.focus(); return; }

  if (loading) loading.style.display = 'flex';
  if (summary) summary.style.display = 'none';
  if (vulnsRow) vulnsRow.style.display = 'none';
  if (grid) grid.innerHTML = '';
  if (emptyEl) emptyEl.style.display = 'none';
  if (errEl) errEl.style.display = 'none';
  if (btn) btn.disabled = true;

  try {
    const res  = await fetch(`/api/exposure?target=${encodeURIComponent(target)}`);
    const data = await res.json();

    if (!res.ok) {
      if (errEl) { errEl.textContent = '⚠️ ' + (data.error || 'Error desconocido'); errEl.style.display = 'block'; }
      return;
    }

    const sum = data.summary || {};
    const setEl = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    setEl('exp-stat-ips',   sum.found_ips ?? '—');
    setEl('exp-stat-ports', sum.total_ports ?? '—');
    setEl('exp-stat-vulns', sum.total_vulns ?? '—');

    const tagsEl = document.getElementById('exp-stat-tags');
    if (tagsEl) {
      tagsEl.innerHTML = (sum.all_tags || []).map(t =>
        `<span class="exp-tag-chip">${escHtml(t)}</span>`
      ).join('') || '<span style="color:var(--text3);font-size:.75rem">—</span>';
    }

    if (summary) summary.style.display = 'grid';

    if ((sum.all_vulns || []).length) {
      const chipsEl = document.getElementById('exp-vuln-chips');
      if (chipsEl) {
        chipsEl.innerHTML = sum.all_vulns.map(v =>
          `<span class="exp-vuln-chip">${escHtml(v)}</span>`
        ).join('');
      }
      if (vulnsRow) vulnsRow.style.display = 'block';
    }

    if (grid) {
      grid.innerHTML = (data.ips || []).map(ip => _renderIPCard(ip)).join('');
    }

    if (!data.ips || !data.ips.length) {
      if (emptyEl) emptyEl.style.display = 'flex';
    }
  } catch (e) {
    if (errEl) { errEl.textContent = '⚠️ Error de conexión al consultar Shodan InternetDB.'; errEl.style.display = 'block'; }
  } finally {
    if (loading) loading.style.display = 'none';
    if (btn) btn.disabled = false;
  }
}

function _renderIPCard(ip) {
  const found = ip.found;
  const ports = ip.ports || [];
  const vulns = ip.vulns || [];
  const tags  = ip.tags  || [];
  const hosts = ip.hostnames || [];
  const cpes  = ip.cpes  || [];

  const portChips = ports.slice(0, 20).map(p =>
    `<span class="exp-port-chip">${p}</span>`
  ).join('');
  const morePortsLabel = ports.length > 20
    ? `<span class="exp-port-more">+${ports.length - 20} más</span>` : '';

  const vulnChips = vulns.slice(0, 8).map(v =>
    `<span class="exp-vuln-chip-sm">${escHtml(v)}</span>`
  ).join('');

  const tagChips = tags.map(t =>
    `<span class="exp-tag-chip-sm">${escHtml(t)}</span>`
  ).join('');

  const hostnamesHtml = hosts.length
    ? `<div class="exp-ip-row"><span class="exp-ip-key">Hostnames</span><span class="exp-ip-val">${hosts.slice(0,4).map(h => escHtml(h)).join(', ')}</span></div>`
    : '';

  if (!found) {
    return `
      <div class="exp-ip-card exp-ip-notfound">
        <div class="exp-ip-header">
          <span class="exp-ip-addr">${escHtml(ip.ip)}</span>
          <span class="exp-ip-badge notfound">Sin datos</span>
        </div>
        <div class="exp-ip-nodesc">No encontrado en Shodan InternetDB${ip.error ? ` — ${escHtml(ip.error)}` : ''}</div>
      </div>`;
  }

  return `
    <div class="exp-ip-card">
      <div class="exp-ip-header">
        <span class="exp-ip-addr">${escHtml(ip.ip)}</span>
        ${vulns.length ? `<span class="exp-ip-badge vuln">${vulns.length} CVE${vulns.length > 1 ? 's' : ''}</span>` : ''}
        ${tags.length  ? `<span class="exp-ip-badge tag">${tags.join(', ')}</span>` : ''}
      </div>
      ${hostnamesHtml}
      ${ports.length ? `
        <div class="exp-ip-row">
          <span class="exp-ip-key">Puertos (${ports.length})</span>
          <div class="exp-port-list">${portChips}${morePortsLabel}</div>
        </div>` : ''}
      ${vulns.length ? `
        <div class="exp-ip-row">
          <span class="exp-ip-key">CVEs</span>
          <div class="exp-port-list">${vulnChips}${vulns.length > 8 ? `<span class="exp-port-more">+${vulns.length - 8} más</span>` : ''}</div>
        </div>` : ''}
      ${tags.length ? `
        <div class="exp-ip-row">
          <span class="exp-ip-key">Tags</span>
          <div class="exp-port-list">${tagChips}</div>
        </div>` : ''}
      ${cpes.length ? `
        <div class="exp-ip-row">
          <span class="exp-ip-key">CPEs</span>
          <span class="exp-ip-val exp-ip-val-mono">${cpes.slice(0,2).map(c => escHtml(c)).join(', ')}</span>
        </div>` : ''}
    </div>`;
}

/* ═══════════════════════════════════════════════
   BREACHES TABS
═══════════════════════════════════════════════ */

function switchBreachTab(tab, btn) {
  document.querySelectorAll('#panel-breaches .out-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.br-tab-pane').forEach(p => { p.style.display = 'none'; });
  if (btn) btn.classList.add('active');
  const pane = document.getElementById('br-pane-' + tab);
  if (pane) pane.style.display = 'block';
}

/* ═══════════════════════════════════════════════
   HARVEST + BREACHES MODULE  (theHarvester → h8mail)
═══════════════════════════════════════════════ */

async function searchHarvestBreaches() {
  const inp      = document.getElementById('harvest-target-input');
  const domain   = inp ? inp.value.trim() : '';
  const loading  = document.getElementById('harvest-loading');
  const loadMsg  = document.getElementById('harvest-loading-msg');
  const results  = document.getElementById('harvest-results');
  const list     = document.getElementById('harvest-results-list');
  const emptyEl  = document.getElementById('harvest-empty');
  const errEl    = document.getElementById('harvest-error');
  const stats    = document.getElementById('harvest-stats');
  const statEl   = document.getElementById('harvest-stat-emails');
  const btn      = document.getElementById('harvest-search-btn');

  if (!domain) { if (inp) inp.focus(); return; }

  if (loading) { loadMsg.textContent = 'Buscando emails del dominio con theHarvester...'; loading.style.display = 'flex'; }
  if (results) results.style.display = 'none';
  if (emptyEl) emptyEl.style.display = 'none';
  if (errEl)   errEl.style.display   = 'none';
  if (stats)   stats.style.display   = 'none';
  if (btn)     btn.disabled = true;

  try {
    const res  = await fetch(`/api/harvest-breaches?target=${encodeURIComponent(domain)}`);
    const data = await res.json();

    if (!res.ok || data.error) {
      if (errEl) { errEl.textContent = '⚠️ ' + (data.error || 'Error desconocido'); errEl.style.display = 'block'; }
      return;
    }

    if (statEl) statEl.textContent = data.emails_found ?? 0;
    if (stats)  stats.style.display = 'flex';

    if (!data.results || data.results.length === 0) {
      if (emptyEl) {
        emptyEl.querySelector('.news-empty-title').textContent = 'Sin emails encontrados';
        emptyEl.querySelector('.news-empty-text').textContent =
          data.note || `theHarvester no encontró emails para "${escHtml(domain)}" en fuentes pasivas.`;
        emptyEl.style.display = 'flex';
      }
      return;
    }

    if (list)    list.innerHTML = data.results.map(_renderH8mailResult).join('');
    if (results) results.style.display = 'block';

  } catch (e) {
    if (errEl) { errEl.textContent = '⚠️ Error de conexión.'; errEl.style.display = 'block'; }
  } finally {
    if (loading) loading.style.display = 'none';
    if (btn)     btn.disabled = false;
  }
}

/* ═══════════════════════════════════════════════
   BREACHES MODULE  (h8mail + Leak-Lookup)
═══════════════════════════════════════════════ */

async function searchBreaches() {
  const inp     = document.getElementById('breaches-target-input');
  const target  = inp ? inp.value.trim() : '';
  const loading = document.getElementById('breaches-loading');
  const results = document.getElementById('breaches-results');
  const emptyEl = document.getElementById('breaches-empty');
  const errEl   = document.getElementById('breaches-error');
  const btn     = document.getElementById('breaches-search-btn');
  const list    = document.getElementById('br-results-list');

  if (!target) { if (inp) inp.focus(); return; }

  if (loading) loading.style.display = 'flex';
  if (results) results.style.display = 'none';
  if (emptyEl) emptyEl.style.display = 'none';
  if (errEl)   errEl.style.display   = 'none';
  if (btn)     btn.disabled = true;

  try {
    const res  = await fetch(`/api/breaches?target=${encodeURIComponent(target)}`);
    const data = await res.json();

    if (!res.ok || data.error) {
      if (errEl) { errEl.textContent = '⚠️ ' + (data.error || 'Error desconocido'); errEl.style.display = 'block'; }
      return;
    }

    if (list) list.innerHTML = (data.results || []).map(_renderH8mailResult).join('');
    if (results) results.style.display = 'block';

  } catch (e) {
    if (errEl) { errEl.textContent = '⚠️ Error de conexión al ejecutar h8mail.'; errEl.style.display = 'block'; }
  } finally {
    if (loading) loading.style.display = 'none';
    if (btn)     btn.disabled = false;
  }
}

function _renderH8mailResult(r) {
  const pwned   = r.pwn_num > 0;
  const sources = r.sources || [];

  const sourceChips = sources.map(s => {
    const label = s.breach || s.source;
    const src   = (s.source || '').replace('LEAKLOOKUP_PUB', 'Leak-Lookup').replace('HUNTER_PUB', 'Hunter.io');
    return `<div class="br-source-row">
      <span class="br-source-tag">${escHtml(src)}</span>
      <span class="br-source-breach">${escHtml(label)}</span>
    </div>`;
  }).join('');

  return `
    <div class="br-result-card ${pwned ? 'br-pwned' : 'br-clean'}">
      <div class="br-result-header">
        <span class="br-result-target">${escHtml(r.target)}</span>
        ${pwned
          ? `<span class="br-result-badge pwned">💥 ${r.pwn_num} brecha${r.pwn_num > 1 ? 's' : ''}</span>`
          : `<span class="br-result-badge clean">✅ Sin brechas</span>`
        }
      </div>
      ${pwned ? `<div class="br-source-list">${sourceChips}</div>` : ''}
    </div>`;
}

// ── Urlscan.io ────────────────────────────────────────────────────────────────

async function urlscanSearch() {
  const inp = $('us-input');
  const q = inp ? inp.value.trim() : '';
  if (!q) { showToast('Introduce un dominio o URL', 'error'); return; }

  $('us-status').style.display = 'flex';
  $('us-results').style.display = 'none';
  $('us-empty').style.display = 'none';

  try {
    const res = await fetch(`/api/urlscan/search?q=${encodeURIComponent(q)}`);
    const data = await res.json();
    $('us-status').style.display = 'none';

    if (data.error) { showToast(data.error, 'error'); return; }

    const grid = $('us-results');
    if (!data.results || data.results.length === 0) {
      $('us-empty').style.display = 'flex';
      return;
    }

    grid.innerHTML = data.results.map(r => {
      const date = r.date ? new Date(r.date).toLocaleDateString('es-ES') : '—';
      const malBadge = r.malicious
        ? `<span class="us-badge us-malicious">⚠ Malicioso</span>`
        : `<span class="us-badge us-clean">✓ Limpio</span>`;
      const tags = (r.tags || []).map(t => `<span class="us-tag">${escHtml(t)}</span>`).join('');
      return `
        <div class="us-card">
          <a class="us-screenshot-wrap" href="${escHtml(r.result_url)}" target="_blank" rel="noopener">
            <img class="us-screenshot" src="${escHtml(r.screenshot)}" alt="screenshot" loading="lazy" onerror="this.style.display='none'">
          </a>
          <div class="us-card-body">
            <div class="us-card-top">
              <span class="us-domain">${escHtml(r.domain || r.url)}</span>
              ${malBadge}
            </div>
            <div class="us-meta">
              <span>🌍 ${escHtml(r.country || '—')}</span>
              <span>📡 ${escHtml(r.ip || '—')}</span>
              <span>🏢 ${escHtml(r.asnname || r.asn || '—')}</span>
              <span>🖥 ${escHtml(r.server || '—')}</span>
              <span>📅 ${date}</span>
            </div>
            ${tags ? `<div class="us-tags">${tags}</div>` : ''}
            <a class="us-link" href="${escHtml(r.result_url)}" target="_blank" rel="noopener">Ver reporte completo →</a>
          </div>
        </div>`;
    }).join('');

    grid.style.display = 'grid';
  } catch (err) {
    $('us-status').style.display = 'none';
    showToast('Error al consultar urlscan.io', 'error');
  }
}

async function urlscanSubmit() {
  const inp = $('us-input');
  const url = inp ? inp.value.trim() : '';
  if (!url) { showToast('Introduce un dominio o URL', 'error'); return; }

  const btn = $('us-scan-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Enviando...'; }

  try {
    const res = await fetch('/api/urlscan/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    if (data.error) {
      showToast(data.error, 'error');
    } else {
      showToast(`Escaneo enviado. Resultado en: ${data.result_url}`, 'success', 6000);
      window.open(data.result_url, '_blank');
    }
  } catch (err) {
    showToast('Error al enviar el escaneo', 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '+ Nuevo escaneo'; }
  }
}
