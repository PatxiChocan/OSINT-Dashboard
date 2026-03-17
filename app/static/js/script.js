const UI_TEXT = {
  emptySummary: 'Selecciona una subherramienta y pulsa Ejecutar.',
  emptyParallel: 'Selecciona herramientas arriba y pulsa Lanzar.',
  emptyStructured: 'No se encontraron datos estructurados. Revisa el output completo.',
  missingCommand: 'Selecciona una subherramienta o escribe un comando.',
  missingTarget: 'Introduce un objetivo real arriba antes de ejecutar.',
  running: 'Ejecutando...',
  runningFromPlan: 'Ejecutando desde plan...'
};

setInterval(() => {
  const clock = document.getElementById('clock');
  if (clock) {
    clock.textContent = new Date().toLocaleTimeString('es-ES');
  }
}, 1000);

let target = '';
const runningRequests = {};
const selectedSubtool = {};

const TOOL_COLORS = {
  discover: { bg: '#fff7ed', color: '#c2410c', border: '#fed7aa' },
  amass: { bg: '#eff6ff', color: '#1d4ed8', border: '#bfdbfe' },
  katana: { bg: '#f5f3ff', color: '#6d28d9', border: '#ddd6fe' }
};

const SUBTOOLS = {
  discover: [
    { name: 'theHarvester', func: 'Emails, subdominios, IPs desde APIs OSINT', alert: 'none', cmd: t => `theHarvester -d ${t} -b all` },
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
    { name: 'intel', func: 'Dominios por WHOIS inverso y ASNs', alert: 'none', cmd: t => `amass intel -d ${t}` },
    { name: 'enum -passive', func: 'Subdominios solo con fuentes OSINT', alert: 'none', cmd: t => `amass enum -passive -d ${t}` },
    { name: 'enum -active', func: 'Valida subdominios con DNS activo', alert: 'low', cmd: t => `amass enum -active -d ${t}` },
    { name: 'enum -brute', func: 'Fuerza bruta DNS con resolvers públicos', alert: 'med', cmd: t => `amass enum -brute -r 8.8.8.8,1.1.1.1 -dns-qps 30 -d ${t}` },
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
  document.querySelectorAll('.panel').forEach(panel => panel.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(button => button.classList.remove('active'));

  const panel = $(`panel-${id}`);
  if (panel) panel.classList.add('active');

  if (btn) {
    btn.classList.add('active');
    return;
  }

  const matching = [...document.querySelectorAll('.nav-btn')].find(button =>
    button.textContent.trim().toLowerCase().includes(id.toLowerCase())
  );
  if (matching) matching.classList.add('active');
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
            <button class="out-tab" onclick="switchTab('${tool}','raw',this)">Output completo</button>
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
              Ejecutando...
            </div>
            <div class="status-done" id="sd-${tool}">✓ Completado</div>
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
    const section = document.createElement('div');
    section.className = 'parallel-tool-section';

    section.innerHTML = `
      <div class="parallel-tool-header">
        <span class="parallel-tool-badge"
          style="background:${color.bg};color:${color.color};border:1px solid ${color.border}">
          ${tool.toUpperCase()}
        </span>
        ${toolMeta[tool].title.replace(/^.\s/, '')}
      </div>
      <div class="parallel-tool-grid" id="psg-${tool}"></div>
    `;

    parallelGrid.appendChild(section);

    SUBTOOLS[tool].forEach((subtool, idx) => {
      const card = document.createElement('div');
      card.className = 'subtool-card parallel-select-card';

      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.className = 'parallel-checkbox';
      checkbox.dataset.tool = tool;
      checkbox.dataset.idx = idx;
      checkbox.onchange = updateParallelCount;

      card.appendChild(checkbox);
      card.insertAdjacentHTML('beforeend', `
        <div class="sc-top">
          <span class="sc-name">${subtool.name}</span>
          ${alertBadge(subtool.alert)}
        </div>
        <div class="sc-func">${subtool.func}</div>
      `);

      card.onclick = (event) => {
        if (event.target !== checkbox) {
          checkbox.checked = !checkbox.checked;
          updateParallelCount();
        }
      };

      $(`psg-${tool}`).appendChild(card);
    });
  });
}

function updateParallelCount() {
  const checked = document.querySelectorAll('#parallel-subtool-grid input[type=checkbox]:checked').length;
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
  const isWhoisOutput = /Domain Name:|Registrar:|Name Server:|WHOIS/i.test(joined);

  const whatwebData = collectWhatWebData(lines);
  const looksLikeWhatWeb = whatwebData.urls.length || whatwebData.ips.length || whatwebData.titles.length || whatwebData.servers.length || whatwebData.technologies.length;

  if (looksLikeWhatWeb) {
    if (whatwebData.urls.length) {
      groups.push({ title: 'URLs analizadas', icon: '🔗', type: 'url', items: whatwebData.urls });
    }

    if (whatwebData.ips.length) {
      groups.push({ title: 'IPs detectadas', icon: '📡', type: 'ip', items: whatwebData.ips });
    }

    if (whatwebData.titles.length) {
      groups.push({ title: 'Títulos', icon: '📰', type: 'generic', items: whatwebData.titles });
    }

    if (whatwebData.servers.length) {
      groups.push({ title: 'Servidor web', icon: '🖥️', type: 'generic', items: whatwebData.servers });
    }

    if (whatwebData.technologies.length) {
      groups.push({ title: 'Tecnologías detectadas', icon: '🧩', type: 'generic', items: whatwebData.technologies });
    }

    return groups;
  }

  if (['discover', 'amass'].includes(tool)) {
    const emails = [...new Set(
      lines.flatMap(line => line.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || [])
    )];

    if (emails.length) {
      groups.push({ title: 'Emails', icon: '✉️', type: 'email', items: emails });
    }

    let hosts = [...new Set(
      lines.flatMap(line => line.match(/(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}/gi) || [])
        .map(host => host.trim().toLowerCase())
        .filter(host => !host.match(/^\d/) && host.split('.').length >= 2 && host.length > 5)
    )];

    if (isWhoisOutput) {
      const noiseHosts = new Set([
        'icann.org',
        'www.icann.org',
        'internic.net',
        'wdprs.internic.net',
        'networksolutions.com',
        'whois.networksolutions.com',
        'maskeddetails.com'
      ]);

      const nsMatches = [...joined.matchAll(/Name Server:\s*([^\n]+)/gi)]
        .map(match => match[1].trim().toLowerCase());

      const domainMatch = joined.match(/Domain Name:\s*([^\n]+)/i);
      const mainDomain = domainMatch ? domainMatch[1].trim().toLowerCase() : null;

      hosts = hosts.filter(host => {
        if (noiseHosts.has(host)) return false;
        if (host.includes('http://') || host.includes('https://')) return false;
        if (host.includes('/')) return false;
        if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host)) return false;
        if (host.split('.').some(part => !part || part.length > 63)) return false;
        return true;
      });

      hosts = hosts.filter(host => host === mainDomain || nsMatches.includes(host));
    }

    if (hosts.length) {
      groups.push({ title: 'Hosts / Subdominios', icon: '🌐', type: 'host', items: hosts });
    }

    const ips = [...new Set(
      lines.flatMap(line => line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])
    )];

    if (ips.length) {
      groups.push({ title: 'IPs', icon: '📡', type: 'ip', items: ips });
    }
  }

  if (tool === 'discover') {
    const domainMatch = joined.match(/Domain Name:\s*([^\n]+)/i);
    const registrarMatch = joined.match(/Registrar:\s*([^\n]+)/i);
    const creationMatch = joined.match(/Creation Date:\s*([^\n]+)/i);
    const expiryMatch =
      joined.match(/Registry Expiry Date:\s*([^\n]+)/i) ||
      joined.match(/Registrar Registration Expiration Date:\s*([^\n]+)/i);

    const nsMatches = [...joined.matchAll(/Name Server:\s*([^\n]+)/gi)]
      .map(match => match[1].trim().toLowerCase());

    const statusMatches = [...joined.matchAll(/Domain Status:\s*([^\n]+)/gi)]
      .map(match => match[1].trim());

    const whoisItems = [];
    if (domainMatch) whoisItems.push(`Dominio: ${domainMatch[1].trim()}`);
    if (registrarMatch) whoisItems.push(`Registrador: ${registrarMatch[1].trim()}`);
    if (creationMatch) whoisItems.push(`Creado: ${creationMatch[1].trim()}`);
    if (expiryMatch) whoisItems.push(`Expira: ${expiryMatch[1].trim()}`);

    if (whoisItems.length) {
      groups.unshift({
        title: 'Resumen WHOIS',
        icon: '📇',
        type: 'generic',
        items: whoisItems
      });
    }

    if (nsMatches.length) {
      groups.push({
        title: 'Name Servers',
        icon: '🧭',
        type: 'host',
        items: [...new Set(nsMatches)]
      });
    }

    if (statusMatches.length) {
      groups.push({
        title: 'Estados del dominio',
        icon: '🛡️',
        type: 'generic',
        items: [...new Set(statusMatches)]
      });
    }
  }

  if (tool === 'katana') {
    const urls = [...new Set(
      lines.flatMap(line => line.match(/https?:\/\/[^\s]+/g) || [])
    )];

    if (urls.length) {
      groups.push({ title: 'URLs encontradas', icon: '🔗', type: 'url', items: urls });
    }
  }

  const ports = lines.filter(line => /\d+\/(tcp|udp)\s+(open|closed|filtered)/i.test(line));
  if (ports.length) {
    groups.push({ title: 'Puertos', icon: '🔌', type: 'generic', items: ports });
  }

  return groups;
}

function renderParsed(tool, groups) {
  const container = $(`results-${tool}`);
  if (!container) return;

  if (!groups.length) {
    container.innerHTML = makeInfoText(UI_TEXT.emptyStructured);
    return;
  }

  container.innerHTML = groups.map(group => `
    <div class="result-group">
      <div class="rg-title">
        ${group.icon} ${group.title}
        <span class="rg-count">${group.items.length}</span>
      </div>
      <div class="result-items">
        ${group.items.map(item => `<div class="result-item ${group.type}">${escHtml(item)}</div>`).join('')}
      </div>
    </div>
  `).join('');
}

function createBufferedWriter(rawOutput) {
  let buffer = [];
  let timer = null;

  function flush() {
    if (!rawOutput || !buffer.length) return;
    rawOutput.textContent += buffer.join('');
    buffer = [];
    rawOutput.scrollTop = rawOutput.scrollHeight;
    timer = null;
  }

  return {
    write(text) {
      buffer.push(text);
      if (!timer) {
        timer = setTimeout(flush, 120);
      }
    },
    flushNow() {
      flush();
    }
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
  if (rawOutput) rawOutput.textContent = '';

  const writer = createBufferedWriter(rawOutput);

  setStatus(tool, 'running');
  if ($(`run-${tool}`)) $(`run-${tool}`).disabled = true;
  if ($(`stop-${tool}`)) $(`stop-${tool}`).style.display = 'inline-block';
  setHtml(`results-${tool}`, makeInfoText(UI_TEXT.running));

  const allLines = [];
  const requestId = crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random());
  runningRequests[tool] = requestId;

  streamCmd(
    cmd,
    requestId,
    (msg) => {
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
        writer.write(`⚠ Process finished with code ${msg.message}\n`);
        return;
      }

      if (msg.type === 'error') {
        writer.flushNow();
        setHtml(`results-${tool}`, makeInfoText(`Error: ${msg.message}`, 'error'));
        writer.write(`✖ ${msg.message}\n`);
        return;
      }

      if (msg.type === 'done') {
        writer.flushNow();
        setStatus(tool, 'done');
        renderParsed(tool, parseOutput(tool, allLines));
        resetBtn(tool);
        delete runningRequests[tool];
      }
    },
    (err) => {
      writer.flushNow();
      setHtml(`results-${tool}`, makeInfoText(`Error: ${err}`, 'error'));
      resetBtn(tool);
      delete runningRequests[tool];
    }
  );
}

function launchParallel() {
  const checked = [...document.querySelectorAll('#parallel-subtool-grid input[type=checkbox]:checked')];
  if (!checked.length) return;

  const parallelOut = $('parallel-out');
  parallelOut.innerHTML = '';

  const launchBtn = $('launch-parallel-btn');
  if (launchBtn) launchBtn.disabled = true;

  checked.forEach(checkbox => {
    const tool = checkbox.dataset.tool;
    const idx = parseInt(checkbox.dataset.idx, 10);
    const subtool = SUBTOOLS[tool][idx];
    const cmd = subtool.cmd(target || 'OBJETIVO');
    const color = TOOL_COLORS[tool];

    if (cmd.includes('OBJETIVO')) {
      appendParallelLine(tool, `[ERROR] ${UI_TEXT.missingTarget}`, color, false);
      return;
    }

    const requestId = crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random());

    streamCmd(
      cmd,
      requestId,
      (msg) => {
        if (msg.type === 'start') {
          appendParallelLine(tool, `▶ Iniciando: ${msg.message}`, color, true);
        } else if (msg.type === 'line') {
          appendParallelLine(tool, msg.stream === 'stderr' ? `⚠ ${msg.message}` : msg.message, color, false);
        } else if (msg.type === 'exit') {
          appendParallelLine(tool, `⚠ Exit code: ${msg.message}`, color, false);
        } else if (msg.type === 'error') {
          appendParallelLine(tool, `[ERROR] ${msg.message}`, color, false);
        } else if (msg.type === 'done') {
          appendParallelLine(tool, '✓ Completado', color, true);
        }
      },
      (err) => appendParallelLine(tool, `[ERROR] ${err}`, color, false)
    );
  });

  setTimeout(() => {
    if (launchBtn) launchBtn.disabled = false;
  }, 1000);
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
  document.querySelectorAll('#parallel-subtool-grid input[type=checkbox]').forEach(checkbox => {
    checkbox.checked = false;
  });

  updateParallelCount();
  setHtml('parallel-out', `<span class="empty-output-text">${UI_TEXT.emptyParallel}</span>`);
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

  if (rawOutput) rawOutput.textContent = '';
  if (cmdInput) cmdInput.value = cmd;
  if (cmdBox) cmdBox.style.display = 'block';

  const writer = createBufferedWriter(rawOutput);

  setStatus(tool, 'running');
  if ($(`run-${tool}`)) $(`run-${tool}`).disabled = true;
  if ($(`stop-${tool}`)) $(`stop-${tool}`).style.display = 'inline-block';

  setHtml(`results-${tool}`, makeInfoText(UI_TEXT.runningFromPlan));

  const allLines = [];
  const requestId = crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random());
  runningRequests[tool] = requestId;

  streamCmd(
    cmd,
    requestId,
    (msg) => {
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

      if (msg.type === 'error') {
        writer.flushNow();
        setHtml(`results-${tool}`, makeInfoText(`Error: ${msg.message}`, 'error'));
        return;
      }

      if (msg.type === 'done') {
        writer.flushNow();
        setStatus(tool, 'done');
        renderParsed(tool, parseOutput(tool, allLines));
        resetBtn(tool);
        delete runningRequests[tool];
      }
    },
    (err) => {
      writer.flushNow();
      setHtml(`results-${tool}`, makeInfoText(`Error: ${err}`, 'error'));
      resetBtn(tool);
      delete runningRequests[tool];
    }
  );
}

function streamCmd(cmd, requestId, onData, onError) {
  fetch('/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cmd, request_id: requestId })
  })
    .then(async (res) => {
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || 'Error HTTP');
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      function read() {
        reader.read()
          .then(({ done, value }) => {
            if (done) return;

            buffer += decoder.decode(value, { stream: true });
            const chunks = buffer.split('\n\n');
            buffer = chunks.pop();

            chunks.forEach(chunk => {
              const line = chunk.split('\n').find(item => item.startsWith('data:'));
              if (!line) return;

              try {
                const msg = JSON.parse(line.slice(5).trim());
                onData(msg);
              } catch (_) {}
            });

            read();
          })
          .catch(err => onError(err.message));
      }

      read();
    })
    .catch(err => onError(err.message));
}

function setStatus(tool, state) {
  const running = $(`sr-${tool}`);
  const done = $(`sd-${tool}`);
  const idle = $(`ss-${tool}`);

  if (running) running.style.display = state === 'running' ? 'flex' : 'none';
  if (done) done.style.display = state === 'done' ? 'inline' : 'none';
  if (idle) idle.style.display = state === 'running' || state === 'done' ? 'none' : 'inline';
}

function stopTool(tool) {
  const requestId = runningRequests[tool];

  if (!requestId) {
    resetBtn(tool);
    const idle = $(`ss-${tool}`);
    if ($(`sr-${tool}`)) $(`sr-${tool}`).style.display = 'none';
    if (idle) {
      idle.style.display = 'inline';
      idle.textContent = 'Detenido';
    }
    return;
  }

  fetch('/stop', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_id: requestId })
  }).finally(() => {
    resetBtn(tool);

    const running = $(`sr-${tool}`);
    const done = $(`sd-${tool}`);
    const idle = $(`ss-${tool}`);

    if (running) running.style.display = 'none';
    if (done) done.style.display = 'none';
    if (idle) {
      idle.style.display = 'inline';
      idle.textContent = 'Detenido';
    }

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
  setText(`raw-out-${tool}`, '');
  setStatus(tool, 'idle');
}

buildToolPanels();
buildParallelGrid();
updateParallelCount();