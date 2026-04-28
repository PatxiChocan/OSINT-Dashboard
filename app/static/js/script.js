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
  discover: { bg: '#fff7ed', color: '#c2410c', border: '#fed7aa' },
  amass: { bg: '#eff6ff', color: '#1d4ed8', border: '#bfdbfe' },
  katana: { bg: '#f5f3ff', color: '#6d28d9', border: '#ddd6fe' }
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
  ]
};

const toolList = ['discover', 'amass', 'katana'];

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

  Object.keys(selectedSubtool).forEach(tool => {
    const idx = selectedSubtool[tool];
    if (idx !== undefined) buildPreview(tool, idx);
  });
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

function launchParallel() {
  const checked = [...document.querySelectorAll('#parallel-subtool-grid .pg-checkbox:checked')];
  if (!checked.length) return;

  Object.keys(_parallelState).forEach(k => delete _parallelState[k]);
  _parallelTotal = checked.length;
  _parallelDone  = 0;

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

function goToPlan(tool, idx) {
  show(tool, null);
  const card = $(`card-${tool}-${idx}`);

  if (card) {
    selectSubtool(tool, idx, card);
    card.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
}

function runPlanStep(cmdTemplate, tool) {
  const cmd = cmdTemplate.replace(/OBJETIVO/g, target || 'OBJETIVO');
  if (cmd.includes('OBJETIVO')) {
    setHtml(`results-${tool}`, makeInfoText(UI_TEXT.missingTarget, 'error'));
    return;
  }

  show(tool, null);

  const rawOutput = $(`raw-out-${tool}`);
  const cmdInput = $(`cmd-${tool}`);
  const cmdBox = $(`tb-${tool}`);

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
  // reset line-count badge
  const badge = document.querySelector(`#raw-${tool} .line-count-badge`);
  if (badge) badge.textContent = '';
  // reset elapsed done
  const et = $(`et-${tool}`); if (et) et.textContent = '';
  stopTimer(tool);
  setStatus(tool, 'idle');
}

buildToolPanels();
buildParallelGrid();
updateParallelCount();

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
      mainGrid.innerHTML = '<div style="color:var(--red);padding:20px;font-size:.85rem">⚠️ Error al cargar el overview. Comprueba la conexión.</div>';
    }
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
          <span class="cve-id">${c.id}</span>
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