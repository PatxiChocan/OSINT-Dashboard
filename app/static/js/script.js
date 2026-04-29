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
  discover:  { bg: '#fff7ed', color: '#c2410c', border: '#fed7aa' },
  amass:     { bg: '#eff6ff', color: '#1d4ed8', border: '#bfdbfe' },
  katana:    { bg: '#f5f3ff', color: '#6d28d9', border: '#ddd6fe' },
  gitleaks:  { bg: '#fef2f2', color: '#b91c1c', border: '#fecaca' },
  wayback:   { bg: '#f0fdf4', color: '#15803d', border: '#bbf7d0' }
};

const SUBTOOLS = {
  discover: [
    { name: 'theHarvester', func: 'Emails, subdominios, IPs desde APIs OSINT', alert: 'none', cmd: t => `script -q -c "theHarvester -d ${t} -b baidu,certspotter,crtsh,duckduckgo,hackertarget,urlscan" /dev/null` },
    { name: 'DNSRecon', func: 'Registros DNS: A, AAAA, MX, NS, TXT, SOA', alert: 'low', cmd: t => `dnsrecon -d ${t}` },
    { name: 'WHOIS', func: 'Propietario, fechas y nameservers', alert: 'none', cmd: t => `whois ${t}` },
    { name: 'WafW00f', func: 'Detecta y fingerprinta WAFs', alert: 'med', cmd: t => `wafw00f https://${t}` },
    { name: 'WhatWeb', func: 'CMS, frameworks y versiones del servidor', alert: 'low', cmd: t => `timeout 20 whatweb --no-errors ${t}` },
    { name: 'Traceroute', func: 'Ruta de red hasta el objetivo', alert: 'low', cmd: t => `traceroute ${t}` },
    { name: 'Nmap top1000', func: 'SYN scan de los 1000 puertos más comunes', alert: 'high', cmd: t => `nmap -sS -T3 ${t}` },
    { name: 'Nmap + versiones', func: 'Detección de servicios y versiones', alert: 'high', cmd: t => `nmap -sV -T3 ${t}` },
    { name: 'Nmap + NSE', func: 'Scripts NSE automáticos de reconocimiento', alert: 'high', cmd: t => `nmap -sC -sV -T3 ${t}` },
    { name: 'enum4linux', func: 'Usuarios, shares y políticas SMB', alert: 'high', cmd: t => `enum4linux ${t}` },
    { name: 'smbclient', func: 'Recursos compartidos SMB', alert: 'med', cmd: t => `smbclient -L ${t} -N` },
    { name: 'ike-scan', func: 'Gateways VPN IPsec', alert: 'med', cmd: t => `ike-scan ${t}` },
    { name: 'Nikto', func: '5000+ peticiones buscando configs inseguros', alert: 'high', cmd: t => `nikto -h ${t}` },
    { name: 'sslscan', func: 'Versiones TLS, cipher suites y certificados', alert: 'med', cmd: t => `sslscan ${t}` },
    { name: 'sslyze', func: 'Análisis profundo TLS: ROBOT, Heartbleed', alert: 'med', cmd: t => `sslyze ${t}` }
  ],
  amass: [
    { name: 'intel', func: 'Dominios por WHOIS inverso y ASNs', alert: 'none', cmd: t => `amass intel -whois -d ${t}` },
    { name: 'enum -passive', func: 'Subdominios solo con fuentes OSINT', alert: 'none', cmd: t => `amass enum -passive -d ${t}` },
    { name: 'enum -active', func: 'Valida subdominios con DNS activo', alert: 'low', cmd: t => `amass enum -active -d ${t}` },
    { name: 'enum -brute', func: 'Fuerza bruta DNS con resolvers públicos', alert: 'med', cmd: t => `amass enum -brute -r 8.8.8.8,1.1.1.1 -d ${t}` },
    { name: 'track', func: 'Nuevos subdominios vs escaneos anteriores', alert: 'none', cmd: t => `amass track -d ${t}` },
    { name: 'db', func: 'Consulta base de datos local', alert: 'none', cmd: t => `amass db -d ${t}` }
  ],
  katana: [
    { name: 'Estático', func: 'Rastrea HTML sin JS', alert: 'low', cmd: t => `katana -u https://${t} -rl 20 -silent` },
    { name: 'Con JS (-jc)', func: 'Analiza .js buscando endpoints', alert: 'low', cmd: t => `katana -u https://${t} -jc -rl 20 -silent` },
    { name: 'Headless', func: 'Chrome real para ejecutar JS', alert: 'med', cmd: t => `katana -u https://${t} -headless -rl 15 -c 5 -no-sandbox` },
    { name: 'robots + sitemap', func: 'Lee robots.txt y sitemap.xml', alert: 'low', cmd: t => `katana -u https://${t} -kf robotstxt,sitemapxml -rl 20 -silent` },
    { name: 'Deep crawl', func: 'Crawling profundo depth 5', alert: 'med', cmd: t => `katana -u https://${t} -jc -kf robotstxt,sitemapxml -rl 10 -depth 5 -silent` },
    { name: 'Con sesión', func: 'Crawling autenticado con cookie', alert: 'med', cmd: t => `katana -u https://${t} -H "Cookie: session=PEGAR_AQUI" -headless -rl 10` }
  ],
  gitleaks: [
    { name: 'Detectar secretos (dir actual)', func: 'Busca credenciales y tokens en el directorio de trabajo', alert: 'none', cmd: _t => `gitleaks detect --source . --no-git -v` },
    { name: 'Detectar secretos (repo git)', func: 'Escanea historial completo del repositorio git local', alert: 'none', cmd: _t => `gitleaks git --source . -v` },
    { name: 'Directorio /tmp/aletheia', func: 'Escanea ficheros descargados en sesión actual', alert: 'none', cmd: _t => `gitleaks detect --source /tmp/aletheia --no-git -v` }
  ],
  wayback: [
    { name: 'Listar snapshots', func: 'Muestra todas las versiones archivadas del sitio (sin descargar)', alert: 'none', cmd: t => `wayback_machine_downloader https://${t} -p 1` },
    { name: 'Snapshots desde 2020', func: 'Versiones archivadas a partir de enero 2020', alert: 'none', cmd: t => `wayback_machine_downloader https://${t} -f 20200101000000 -p 1` },
    { name: 'Descargar sitio completo', func: 'Descarga la última versión archivada del sitio', alert: 'low', cmd: t => `wayback_machine_downloader https://${t} -d /tmp/aletheia -c 5` }
  ]
};

const toolList = ['discover', 'amass', 'katana', 'gitleaks', 'wayback'];

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
  gitleaks: {
    title: '🔑 Gitleaks',
    desc: 'Detecta credenciales, tokens y secretos filtrados en repositorios y directorios.',
    tags: '<span class="tag tag-mit">MIT</span>'
  },
  wayback: {
    title: '📼 Wayback Machine',
    desc: 'Accede a versiones archivadas de sitios web a través de Internet Archive.',
    tags: '<span class="tag tag-mit">MIT</span>'
  }
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
  if (!parallelGrid) return;

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

  if (looksLikeWhatWeb) {
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
    const subdomains = [...new Set(
      lines.map(l => l.trim()).filter(l => l && /\./.test(l) && !/^\[|^Error/i.test(l))
    )];
    if (subdomains.length) groups.push({ title: `Subdominios (${subdomains.length})`, icon: '🌐', type: 'host', items: subdomains });
    const ips = [...new Set(lines.flatMap(l => l.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))];
    if (ips.length) groups.push({ title: 'IPs', icon: '📡', type: 'ip', items: ips });
    if (groups.length) return groups;
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
let _parallelTotal = 0;
let _parallelDone  = 0;
let _parallelTimer = null;

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

function _renderParallelSummary() {
  const container = $('parallel-summary');
  if (!container) return;

  const entries = Object.entries(_parallelState);
  if (!entries.length) { container.innerHTML = ''; return; }

  container.innerHTML = entries.map(([key, state]) => {
    const color = TOOL_COLORS[state.tool] || { bg: '#f3f4f6', color: '#374151', border: '#d1d5db' };

    const elapsed = state.done
      ? `<span class="ps-time ps-time-done">${_fmtSecs(state.elapsed)}</span>`
      : `<span class="ps-time ps-time-running"><span class="ps-spinner"></span><span id="psum-timer-${key}">0s</span></span>`;

    const statusIcon = state.done ? '✓' : '…';
    const statusCls  = state.done ? 'ps-status-done' : 'ps-status-running';

    let bodyHtml = '';
    if (state.done) {
      const groups = _parallelGroups(state);
      bodyHtml = `<div class="ps-body">${_renderGroupsHtml(groups)}</div>`;
    } else {
      bodyHtml = `<div class="ps-body ps-body-running">
        <p class="ui-message" style="padding:12px 16px">
          <span class="ps-spinner" style="display:inline-block;margin-right:6px"></span>
          Ejecutando… ${state.lines} líneas recibidas
        </p>
      </div>`;
    }

    const cardId = `pscard-${key}`;
    return `<div class="ps-card ${state.done ? 'ps-card-done' : 'ps-card-running'}" id="${cardId}">
      <div class="ps-card-header" onclick="togglePsCard('${cardId}')" style="cursor:pointer">
        <span class="ps-badge" style="background:${color.bg};color:${color.color};border:1px solid ${color.border}">
          ${state.tool.toUpperCase()}
        </span>
        <span class="ps-name">${state.name}</span>
        <span class="ps-status ${statusCls}">${statusIcon}</span>
        ${elapsed}
        <span class="ps-toggle-icon">▾</span>
      </div>
      <div class="ps-body-wrap">
        ${bodyHtml}
      </div>
    </div>`;
  }).join('');
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

function launchParallel() {
  const checked = [...document.querySelectorAll('#parallel-subtool-grid .pg-checkbox:checked')];
  if (!checked.length) return;

  Object.keys(_parallelState).forEach(k => delete _parallelState[k]);
  _parallelTotal = checked.length;
  _parallelDone  = 0;

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

  checked.forEach(checkbox => {
    const tool = checkbox.dataset.tool;
    const idx  = parseInt(checkbox.dataset.idx, 10);
    const key  = _parallelKey(tool, idx);
    const subtool = SUBTOOLS[tool][idx];
    const cmd  = subtool.cmd(target || 'OBJETIVO');
    const color = TOOL_COLORS[tool];

    if (cmd.includes('OBJETIVO')) {
      appendParallelLine(tool, `[ERROR] ${UI_TEXT.missingTarget}`, color, false);
      _parallelTotal--;
      return;
    }

    _parallelState[key] = {
      tool,
      idx,
      name: subtool.name,
      cmd,
      startTime: Date.now(),
      done: false,
      lines: 0,
      structured: null,
      elapsed: 0,
      hadError: false
    };
    _renderParallelSummary();

    const requestId = crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random());
    const allLines = [];

    streamCmd(
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

          // Persist to sessionStorage for report generation
          _saveParallelRun(tool, subtool, _parallelState[key]);

          if (_parallelState[key].hadError) {
            appendParallelLine(tool, `✖ ${subtool.name} finalizó con error en ${_fmtSecs(_parallelState[key].elapsed)}`, color, true);
          } else {
            appendParallelLine(tool, `✓ ${subtool.name} completado en ${_fmtSecs(_parallelState[key].elapsed)}`, color, true);
          }

          _renderParallelSummary();

          if (_parallelDone >= _parallelTotal) {
            _stopParallelTimer();
            _notifyParallelDone();
            showToast(`Modo paralelo completado — ${_parallelTotal} herramienta${_parallelTotal === 1 ? '' : 's'} finalizadas`, 'success', 5000);
            if (launchBtn) launchBtn.disabled = false;
          }
        }
      },
      (err) => {
        _parallelState[key].done = true;
        _parallelState[key].hadError = true;
        _parallelState[key].elapsed = Math.floor((Date.now() - _parallelState[key].startTime) / 1000);
        _parallelState[key].allLines = allLines;
        _parallelDone++;

        _saveParallelRun(tool, subtool, _parallelState[key]);
        appendParallelLine(tool, `[ERROR] ${err}`, color, false);
        _renderParallelSummary();

        if (_parallelDone >= _parallelTotal) {
          _stopParallelTimer();
          if (launchBtn) launchBtn.disabled = false;
        }
      }
    );
  });
}

function switchParallelTab(tab, btn) {
  document.querySelectorAll('.parallel-tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.output-section .out-tab').forEach(el => el.classList.remove('active'));
  const el = $(`ptab-${tab}`);
  if (el) el.classList.add('active');
  if (btn) btn.classList.add('active');
}

function appendParallelLine(tool, message, color, isHeader = false) {
  const output = $('parallel-out');
  if (!output) return;

  const line = document.createElement('div');
  line.className = 'pline';
  line.innerHTML = `
    <span class="ptag" style="background:${color.bg};color:${color.color};border:1px solid ${color.border}">
      ${tool}
    </span>
    <span class="ptext ${isHeader ? 'ptext-strong' : ''}">${escHtml(message)}</span>
  `;
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
  _parallelTotal = 0;
  _parallelDone  = 0;
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
    <span class="empty-output-text">Esperando selección de herramientas...</span>
  </div>
`);
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
    client:      ($('scope-client')  || {}).value?.trim() || '',
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

function clearScope() {
  localStorage.removeItem(SCOPE_KEY);
  ['scope-case','scope-client','scope-resp','scope-domains','scope-ips','scope-expiry'].forEach(id => {
    const el = $(id); if (el) el.value = '';
  });
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
    set('scope-client',  scope.client);
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
      // Domains as clickable target buttons
      const domainChips = (scope.domains || []).map(d =>
        `<span class="scope-domain-chip" onclick="setTargetFromScope('${escHtml(d)}')" title="Establecer como objetivo activo">
          ${escHtml(d)} <span class="scope-chip-arrow">→</span>
        </span>`
      ).join('');

      const fields = [
        ['Cliente',      escHtml(scope.client || '—'), false],
        ['Responsable',  escHtml(scope.responsable || '—'), false],
        ['Dominios aprobados', domainChips || '—', true],
        ['Rangos IP',    escHtml((scope.ipRanges || []).join(', ') || '—'), false],
        ['Expiración',   escHtml(scope.expiry || '—'), false],
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

  // Topbar scope indicator (updated when target changes too)
  _updateScopeIndicator();
}

function setTargetFromScope(domain) {
  const inp = document.getElementById('targetInput');
  if (inp) { inp.value = domain; updateTarget(domain); }
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
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 11px; color: #1a1a1a; background: #fff; padding: 24px 32px; }
  h1 { font-size: 18px; font-weight: 700; margin-bottom: 4px; color: #0a1628; }
  .subtitle { font-size: 10px; color: #666; margin-bottom: 20px; border-bottom: 1px solid #ddd; padding-bottom: 10px; }
  .subtitle span { margin-right: 16px; }
  .section-title { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: #444; border-bottom: 1px solid #e0e0e0; padding-bottom: 4px; margin: 18px 0 10px; }
  /* parsed output */
  .parsed-section table { width: 100%; border-collapse: collapse; font-size: 10px; }
  .parsed-section td, .parsed-section th { border: 1px solid #ddd; padding: 4px 7px; }
  .parsed-section th { background: #f4f4f4; font-weight: 600; }
  .parsed-section .tag, .parsed-section [class*="badge"], .parsed-section [class*="chip"] { display: inline-block; padding: 1px 5px; border-radius: 3px; background: #eee; font-size: 9px; margin: 1px; }
  .parsed-section .ui-message { color: #888; font-style: italic; }
  /* raw output */
  pre { white-space: pre-wrap; word-break: break-all; font-family: 'Courier New', monospace; font-size: 9.5px; background: #f8f8f8; border: 1px solid #e0e0e0; border-radius: 4px; padding: 12px; line-height: 1.5; }
  @media print { body { padding: 12px 16px; } }
</style>
</head>
<body>
  <h1>${title}</h1>
  <div class="subtitle">
    <span><b>Objetivo:</b> ${tgt}</span>
    <span><b>Fecha:</b> ${date}</span>
    <span><b>Tool:</b> ${tool}</span>
  </div>

  <div class="section-title">Resumen</div>
  <div class="parsed-section">${parsedHtml}</div>

  <div class="section-title">Output completo</div>
  <pre>${rawTxt.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</pre>
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
      <div class="rpt-section">
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
      <div class="rpt-section">
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
      <div class="rpt-section">
        <div class="rpt-section-hdr">
          <span class="rpt-section-num">4.${sIdx++}</span>
          <span class="rpt-section-title">Shodan — Exposición de red</span>
          <span class="rpt-section-meta">IP: ${esc(shodanData.ip)} · ${esc(shodanData.org||'—')} · ${esc(shodanData.country||'—')}</span>
        </div>
        ${svcRows ? `<table class="fi-table"><thead><tr><th>Puerto</th><th>Proto</th><th>Servicio / Producto</th><th>Banner</th></tr></thead><tbody>${svcRows}</tbody></table>` : '<p class="dim">Sin servicios expuestos.</p>'}
        <div style="margin-top:12px"><div class="fi-group-hdr">CVEs detectados</div><div style="margin-top:6px">${cveChips}</div></div>
      </div>`;
  }

  if (vtData) {
    const vColor = vtData.verdict === 'malicious' ? '#c62828' : vtData.verdict === 'suspicious' ? '#e65100' : '#2e7d32';
    const vBg    = vtData.verdict === 'malicious' ? '#fff0f0' : vtData.verdict === 'suspicious' ? '#fff8f0' : '#f0fff4';
    const stats  = vtData.stats || {};
    const flagged = (vtData.flagged || []).slice(0, 20);
    toolSections += `
      <div class="rpt-section">
        <div class="rpt-section-hdr">
          <span class="rpt-section-num">4.${sIdx++}</span>
          <span class="rpt-section-title">VirusTotal — Reputación</span>
          <span class="rpt-section-meta">${esc(vtData._target||'—')} · ${esc(vtData.type)}</span>
        </div>
        <div style="background:${vBg};border:1.5px solid ${vColor};border-radius:6px;padding:14px 18px;display:flex;align-items:center;gap:20px;margin-bottom:12px">
          <div style="font-size:20px;font-weight:800;color:${vColor};letter-spacing:.04em">${esc((vtData.verdict||'').toUpperCase())}</div>
          <div style="font-size:10px;color:#333">
            <b>${stats.malicious||0}</b> motores maliciosos ·
            <b>${stats.suspicious||0}</b> sospechosos ·
            <b>${stats.harmless||0}</b> limpios
            <span style="color:#888"> de ${vtData.total_engines||0} motores totales</span>
          </div>
        </div>
        ${flagged.length ? `<table class="fi-table"><thead><tr><th>Motor antivirus</th><th>Resultado</th></tr></thead><tbody>${
          flagged.map(f => `<tr><td>${esc(f.engine)}</td><td style="color:${f.category==='malicious'?'#c62828':'#e65100'};font-weight:600">${esc(f.result||f.category)}</td></tr>`).join('')
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
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Helvetica,Arial,sans-serif;font-size:11px;color:#1a1a2e;background:#fff}
a{color:#1565c0}

/* ── Cover ── */
.cover{background:#0a1628;color:#fff;min-height:100vh;padding:64px 56px;page-break-after:always;display:flex;flex-direction:column;justify-content:space-between}
.cover-top{}
.cover-logo{font-size:10px;font-weight:700;letter-spacing:.25em;text-transform:uppercase;color:#5c8adb;margin-bottom:56px}
.cover-badge{display:inline-block;background:#c62828;color:#fff;font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;padding:3px 10px;border-radius:2px;margin-bottom:20px}
.cover-title{font-size:32px;font-weight:800;line-height:1.2;margin-bottom:10px;color:#fff}
.cover-client{font-size:16px;color:#7aadff;margin-bottom:0}
.cover-bottom{border-top:1px solid #1e3a5f;padding-top:24px}
.cover-meta{display:grid;grid-template-columns:repeat(3,1fr);gap:16px 32px;font-size:10px;color:#8ea8cc}
.cover-meta-item b{display:block;color:#fff;font-size:11px;margin-bottom:3px}
.cover-meta-item{}

/* ── Body layout ── */
.rpt-body{padding:36px 52px}
.rpt-h1{font-size:16px;font-weight:800;color:#0a1628;margin:36px 0 14px;padding-bottom:8px;border-bottom:3px solid #0a1628;display:flex;align-items:center;gap:10px}
.rpt-h1 .h1-num{font-size:10px;font-weight:700;background:#0a1628;color:#fff;padding:2px 8px;border-radius:3px;letter-spacing:.06em}

/* ── Summary cards ── */
.sum-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.sum-card{border:1px solid #dde3f0;border-radius:8px;padding:16px 12px;text-align:center}
.sum-card.red{border-color:#ffcdd2;background:#fff5f5}
.sum-card.amber{border-color:#ffe0b2;background:#fffaf5}
.sum-card.green{border-color:#c8e6c9;background:#f5fff6}
.sum-num{font-size:28px;font-weight:800;color:#0a1628;line-height:1}
.sum-num.red{color:#c62828}
.sum-num.amber{color:#e65100}
.sum-num.green{color:#2e7d32}
.sum-lbl{font-size:9px;text-transform:uppercase;letter-spacing:.08em;color:#888;margin-top:6px}

/* ── Scope table ── */
.scope-table{width:100%;border-collapse:collapse;font-size:10.5px;margin-bottom:0}
.scope-table td{padding:7px 12px;border:1px solid #dde3f0}
.scope-table .sk{font-weight:700;color:#444;background:#f5f7fb;width:180px;text-transform:uppercase;font-size:9px;letter-spacing:.05em}

/* ── Section header ── */
.rpt-section{margin-bottom:32px;padding-bottom:28px;border-bottom:1px solid #eaecf2}
.rpt-section-hdr{display:flex;align-items:baseline;gap:10px;margin-bottom:14px}
.rpt-section-num{font-size:9px;font-weight:700;background:#0a1628;color:#fff;padding:2px 8px;border-radius:3px;letter-spacing:.04em;white-space:nowrap}
.rpt-section-title{font-size:13px;font-weight:700;color:#0a1628}
.rpt-section-meta{font-size:9px;color:#999;margin-left:auto;text-align:right}

/* ── Aggregated tables ── */
.agg-table{width:100%;border-collapse:collapse;font-size:10px;margin-bottom:4px}
.agg-table th{background:#0a1628;color:#fff;padding:6px 10px;text-align:left;font-size:9px;letter-spacing:.05em;font-weight:600}
.agg-table td{padding:5px 10px;border-bottom:1px solid #eaecf2;vertical-align:top}
.agg-table tr:nth-child(even) td{background:#f8f9fc}
.src-cell{color:#888;font-size:9px}

/* ── Finding groups ── */
.fi-group{margin-bottom:14px}
.fi-group-hdr{font-size:10px;font-weight:700;color:#0a1628;background:#eef1f8;padding:5px 10px;border-radius:4px 4px 0 0;border:1px solid #dde3f0;border-bottom:none}
.fi-table{width:100%;border-collapse:collapse;font-size:10px;border:1px solid #dde3f0;border-radius:0 0 4px 4px;overflow:hidden}
.fi-table th{background:#f0f3fa;color:#333;padding:5px 10px;text-align:left;font-size:9px;letter-spacing:.04em;font-weight:700;border-bottom:1px solid #dde3f0}
.fi-table td{padding:5px 10px;border-bottom:1px solid #eaecf2;vertical-align:top}
.fi-table tr:last-child td{border-bottom:none}
.fi-table tr:nth-child(even) td{background:#f8f9fc}
.fi-key{font-weight:600;color:#444;background:#f5f7fb!important;width:160px;white-space:nowrap;font-size:9.5px}
.fi-list td{font-family:'Courier New',monospace;font-size:9.5px}
.banner-cell{font-family:'Courier New',monospace;font-size:8.5px;color:#555;max-width:200px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* ── CVE chips ── */
.rpt-cve{display:inline-block;background:#fff0f0;border:1px solid #ffcdd2;color:#c62828;border-radius:3px;padding:2px 7px;font-family:monospace;font-size:9px;margin:2px}

/* ── Appendix ── */
.rpt-appendix-note{font-size:9.5px;color:#888;font-style:italic;margin-bottom:20px;padding:8px 12px;background:#fffde7;border-left:3px solid #f9a825;border-radius:2px}
.rpt-appendix-tool{margin-bottom:24px}
.rpt-appendix-title{font-size:10px;font-weight:700;background:#1e3a5f;color:#fff;padding:6px 12px;border-radius:4px 4px 0 0}
pre{white-space:pre-wrap;word-break:break-all;font-family:'Courier New',monospace;font-size:8px;background:#f8f9fc;border:1px solid #dde3f0;border-top:none;border-radius:0 0 4px 4px;padding:12px;line-height:1.6;color:#222}

.dim{color:#aaa;font-style:italic;font-size:10px}
@media print{
  body{padding:0}
  .cover{page-break-after:always;min-height:100vh}
  .rpt-section{page-break-inside:avoid}
  pre{max-height:none}
}
</style>
</head>
<body>

<!-- COVER -->
<div class="cover">
  <div class="cover-top">
    <div class="cover-logo">Aletheia OSINT Platform</div>
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
  <div class="rpt-h1"><span class="h1-num">01</span> Alcance del encargo</div>
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

  <!-- 02 EXECUTIVE SUMMARY -->
  <div class="rpt-h1"><span class="h1-num">02</span> Resumen ejecutivo</div>
  <div class="sum-grid">
    <div class="sum-card">
      <div class="sum-num">${toolsRun}</div>
      <div class="sum-lbl">Herramientas ejecutadas</div>
    </div>
    <div class="sum-card ${uniqHosts.length ? '' : ''}">
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
  <p style="font-size:10.5px;color:#444;line-height:1.7;margin-bottom:8px">
    En el marco del encargo <b>${esc(scope.caseName||'—')}</b> para <b>${esc(scope.client||'—')}</b>,
    se han ejecutado <b>${toolsRun}</b> módulos de reconocimiento sobre los activos aprobados.
    El análisis ha identificado <b>${uniqHosts.length}</b> subdominios o hosts,
    <b>${uniqIPs.length}</b> direcciones IP y
    <b>${uniqEmails.length}</b> correos electrónicos.
    ${cves.length ? `Se han detectado <b style="color:#c62828">${cves.length} vulnerabilidades CVE</b> activas en el perímetro expuesto.` : 'No se han detectado CVEs activos mediante Shodan.'}
    ${vtVerdict === 'malicious' ? `VirusTotal califica el objetivo como <b style="color:#c62828">MALICIOSO</b>.` : vtVerdict === 'suspicious' ? `VirusTotal califica el objetivo como <b style="color:#e65100">SOSPECHOSO</b>.` : ''}
  </p>

  <!-- 03 CONSOLIDATED INTELLIGENCE -->
  <div class="rpt-h1"><span class="h1-num">03</span> Inteligencia consolidada</div>

  <div class="rpt-section">
    <div class="rpt-section-hdr">
      <span class="rpt-section-num">3.1</span>
      <span class="rpt-section-title">Subdominios y hosts descubiertos</span>
      <span class="rpt-section-meta">${uniqHosts.length} únicos</span>
    </div>
    ${aggTable(uniqHosts, ['Subdominio / Host', 'IP asociada', 'Fuente'])}
  </div>

  <div class="rpt-section">
    <div class="rpt-section-hdr">
      <span class="rpt-section-num">3.2</span>
      <span class="rpt-section-title">Direcciones IP identificadas</span>
      <span class="rpt-section-meta">${uniqIPs.length} únicas</span>
    </div>
    ${aggTable(uniqIPs, ['Dirección IP', 'Fuente'])}
  </div>

  <div class="rpt-section">
    <div class="rpt-section-hdr">
      <span class="rpt-section-num">3.3</span>
      <span class="rpt-section-title">Correos electrónicos hallados</span>
      <span class="rpt-section-meta">${uniqEmails.length} únicos</span>
    </div>
    ${aggTable(uniqEmails, ['Dirección de correo', 'Fuente'])}
  </div>

  ${cves.length ? `
  <div class="rpt-section">
    <div class="rpt-section-hdr">
      <span class="rpt-section-num">3.4</span>
      <span class="rpt-section-title">Vulnerabilidades CVE (Shodan)</span>
      <span class="rpt-section-meta">${cves.length} detectadas en IP ${esc(shodanData?.ip||'—')}</span>
    </div>
    <p style="font-size:10px;color:#555;margin-bottom:10px">Las siguientes vulnerabilidades han sido correlacionadas por Shodan con los servicios expuestos en el perímetro. Se recomienda verificar su aplicabilidad y priorizar su remediación.</p>
    <div>${cves.map(id => `<span class="rpt-cve">${esc(id)}</span>`).join(' ')}</div>
  </div>` : ''}

  <!-- 04 PER-TOOL FINDINGS -->
  <div class="rpt-h1"><span class="h1-num">04</span> Hallazgos por herramienta</div>
  ${toolSections || '<p class="dim">No se han ejecutado herramientas en esta sesión.</p>'}

  <!-- APPENDIX -->
  ${appendix ? `
  <div class="rpt-h1"><span class="h1-num">A</span> Apéndice — Output técnico completo</div>
  <div class="rpt-appendix-note">Esta sección contiene el output en bruto de cada herramienta. Está destinada a uso técnico de referencia, no a la lectura ejecutiva.</div>
  ${appendix}` : ''}

</div><!-- /rpt-body -->
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

function generateSTIX() {
  const scope = getScope() || {};
  const now   = new Date().toISOString();

  function uuid4() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = Math.random() * 16 | 0;
      return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
  }

  const objects = [];
  const reportRefs = [];

  function addObj(obj) { objects.push(obj); reportRefs.push(obj.id); return obj.id; }

  // Identity — client org
  addObj({
    type: 'identity', spec_version: '2.1', id: `identity--${uuid4()}`,
    name: scope.client || scope.caseName || 'Unknown Client',
    identity_class: 'organization', created: now, modified: now,
  });

  // Collect data sources
  let shodanData = null, vtData = null;
  try { shodanData = JSON.parse(sessionStorage.getItem('aletheia_shodan_data') || 'null'); } catch(_) {}
  try { vtData     = JSON.parse(sessionStorage.getItem('aletheia_vt_data')     || 'null'); } catch(_) {}

  // ── Shodan → network observables ──
  if (shodanData?.ip) {
    const ipId = addObj({
      type: 'ipv4-addr', spec_version: '2.1', id: `ipv4-addr--${uuid4()}`,
      value: shodanData.ip,
    });

    // Open port observations
    const portRefs = [ipId];
    (shodanData.services || []).forEach(svc => {
      if (!svc.port) return;
      const ntId = addObj({
        type: 'network-traffic', spec_version: '2.1', id: `network-traffic--${uuid4()}`,
        dst_ref: ipId, dst_port: svc.port,
        protocols: [svc.transport || 'tcp'],
        ...(svc.product ? { extensions: { 'tcp-ext': {} } } : {}),
      });
      portRefs.push(ntId);
    });

    addObj({
      type: 'observed-data', spec_version: '2.1', id: `observed-data--${uuid4()}`,
      created: now, modified: now,
      first_observed: now, last_observed: now,
      number_observed: 1, object_refs: portRefs,
    });

    // Hostnames
    (shodanData.hostnames || []).forEach(hn => {
      addObj({ type: 'domain-name', spec_version: '2.1', id: `domain-name--${uuid4()}`, value: hn });
    });

    // CVEs → vulnerability SDOs
    (shodanData.vulns || []).forEach(cveId => {
      addObj({
        type: 'vulnerability', spec_version: '2.1', id: `vulnerability--${uuid4()}`,
        name: cveId, created: now, modified: now,
        external_references: [{ source_name: 'cve', external_id: cveId,
          url: `https://nvd.nist.gov/vuln/detail/${cveId}` }],
      });
    });
  }

  // ── VirusTotal → indicator (if flagged) ──
  if (vtData && (vtData.verdict === 'malicious' || vtData.verdict === 'suspicious')) {
    const tgt = vtData._target || '';
    let pattern = '';
    if (vtData.type === 'ip')     pattern = `[ipv4-addr:value = '${tgt}']`;
    else if (vtData.type === 'domain') pattern = `[domain-name:value = '${tgt}']`;
    else if (vtData.type === 'hash')   pattern = `[file:hashes.'SHA-256' = '${tgt}']`;
    else if (vtData.type === 'url')    pattern = `[url:value = '${tgt}']`;

    if (pattern) {
      addObj({
        type: 'indicator', spec_version: '2.1', id: `indicator--${uuid4()}`,
        name: `VT — ${tgt}`,
        description: `VirusTotal verdict: ${vtData.verdict}. ${vtData.stats?.malicious||0} malicious / ${vtData.stats?.suspicious||0} suspicious out of ${vtData.total_engines||0} engines.`,
        indicator_types: vtData.verdict === 'malicious' ? ['malicious-activity'] : ['anomalous-activity'],
        pattern, pattern_type: 'stix', valid_from: now,
        created: now, modified: now,
        labels: ['threat-intelligence'],
      });
    }
  }

  // ── CLI tool outputs — extract IOCs via regex ──
  const seenIPs = new Set(), seenDomains = new Set(), seenCves = new Set(), seenEmails = new Set();
  const ipRe        = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
  const cveRe       = /CVE-\d{4}-\d{4,7}/gi;
  const emailRe     = /[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/gi;
  const privateIpRe = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.)/;

  // Helper: extract IOCs from a raw text string
  function extractIOCs(rawText) {
    (rawText.match(ipRe) || []).forEach(ip => {
      if (!privateIpRe.test(ip) && !seenIPs.has(ip)) {
        seenIPs.add(ip);
        addObj({ type: 'ipv4-addr', spec_version: '2.1', id: `ipv4-addr--${uuid4()}`, value: ip });
      }
    });
    (rawText.match(cveRe) || []).forEach(cve => {
      const id = cve.toUpperCase();
      if (!seenCves.has(id)) {
        seenCves.add(id);
        addObj({ type: 'vulnerability', spec_version: '2.1', id: `vulnerability--${uuid4()}`,
          name: id, created: now, modified: now,
          external_references: [{ source_name: 'cve', external_id: id, url: `https://nvd.nist.gov/vuln/detail/${id}` }] });
      }
    });
    (rawText.match(emailRe) || []).forEach(em => {
      const e = em.toLowerCase();
      if (!seenEmails.has(e)) {
        seenEmails.add(e);
        addObj({ type: 'email-addr', spec_version: '2.1', id: `email-addr--${uuid4()}`, value: e });
      }
    });
  }

  // Individual tool history
  toolList.forEach(tool => {
    try {
      const raw = sessionStorage.getItem(_histKey(tool));
      if (!raw) return;
      const { rawText = '' } = JSON.parse(raw);
      extractIOCs(rawText);
    } catch(_) {}
  });

  // Parallel run history
  try {
    const parallelRuns = JSON.parse(sessionStorage.getItem('aletheia_parallel_runs') || '[]');
    parallelRuns.forEach(r => extractIOCs(r.rawText || ''));
  } catch(_) {}

  // Scope domains as domain-name SCOs
  (scope.domains || []).forEach(d => {
    if (!seenDomains.has(d)) {
      seenDomains.add(d);
      addObj({ type: 'domain-name', spec_version: '2.1', id: `domain-name--${uuid4()}`, value: d });
    }
  });

  // Report SDO (top-level)
  const reportObj = {
    type: 'report', spec_version: '2.1', id: `report--${uuid4()}`,
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
    external_references: [],
  };

  const bundle = {
    type: 'bundle',
    id: `bundle--${uuid4()}`,
    spec_version: '2.1',
    objects: [reportObj, ...objects],
  };

  const json = JSON.stringify(bundle, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `${(scope.caseName || 'aletheia').replace(/[^a-z0-9\-_]/gi, '_')}-stix21.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
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
updateParallelCount();
renderScopeStatus();

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

const _origShow = show;
window.show = function (panel, btn) {
  _origShow(panel, btn);
  if (panel === 'overview' && !_overview.loaded) loadOverview();
  if (panel === 'news' && !_news.loaded) loadNews();
  if (panel === 'cves' && !_cves.loaded) loadCVEs();
  if (panel === 'iocs' && !_iocs.loaded) loadIOCs();
  if (panel === 'sources' && !_sources.loaded) loadSources();
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