setInterval(() => {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString('es-ES');
}, 1000);

let target = '';

function updateTarget(v) {
  target = v;
  const chip = document.getElementById('targetChip');
  chip.textContent = '🎯 ' + v;
  chip.style.display = v ? 'inline' : 'none';

  Object.keys(selectedSubtool).forEach(t => {
    if (selectedSubtool[t] !== undefined) {
      buildPreview(t, selectedSubtool[t]);
    }
  });
}

function show(id, btn) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));

  const p = document.getElementById('panel-' + id);
  if (p) p.classList.add('active');

  if (btn) {
    btn.classList.add('active');
  } else {
    const b = [...document.querySelectorAll('.nav-btn')].find(b =>
      b.textContent.trim().toLowerCase().includes(id.toLowerCase())
    );
    if (b) b.classList.add('active');
  }
}

const TOOL_COLORS = {
  discover:  { bg:'#fff7ed', color:'#c2410c', border:'#fed7aa' },
  amass:     { bg:'#eff6ff', color:'#1d4ed8', border:'#bfdbfe' },
  katana:    { bg:'#f5f3ff', color:'#6d28d9', border:'#ddd6fe' },
  gitleaks:  { bg:'#fdf4ff', color:'#86198f', border:'#f0abfc' },
  wayback:   { bg:'#ecfdf5', color:'#065f46', border:'#6ee7b7' },
  spiderfoot:{ bg:'#fef2f2', color:'#991b1b', border:'#fecaca' },
};

const SUBTOOLS = {
  discover: [
    { name:'theHarvester', func:'Emails, subdominios, IPs desde APIs OSINT', alert:'none', cmd:t => `theHarvester -d ${t} -b all` },
    { name:'DNSRecon', func:'Registros DNS: A, AAAA, MX, NS, TXT, SOA', alert:'low', cmd:t => `dnsrecon -d ${t}` },
    { name:'WHOIS', func:'Propietario, fechas y nameservers', alert:'none', cmd:t => `whois ${t}` },
    { name:'WafW00f', func:'Detecta y fingerprinta WAFs', alert:'med', cmd:t => `wafw00f https://${t}` },
    { name:'WhatWeb', func:'CMS, frameworks y versiones del servidor', alert:'low', cmd:t => `whatweb ${t}` },
    { name:'Traceroute', func:'Ruta de red hasta el objetivo', alert:'low', cmd:t => `traceroute ${t}` },
    { name:'Nmap top1000', func:'SYN scan de los 1000 puertos más comunes', alert:'high', cmd:t => `nmap -sS -T3 ${t}` },
    { name:'Nmap + versiones', func:'Detección de servicios y versiones', alert:'high', cmd:t => `nmap -sV -T3 ${t}` },
    { name:'Nmap + NSE', func:'Scripts NSE automáticos de reconocimiento', alert:'high', cmd:t => `nmap -sC -sV -T3 ${t}` },
    { name:'enum4linux', func:'Usuarios, shares y políticas SMB', alert:'high', cmd:t => `enum4linux ${t}` },
    { name:'smbclient', func:'Recursos compartidos SMB', alert:'med', cmd:t => `smbclient -L ${t} -N` },
    { name:'ike-scan', func:'Gateways VPN IPsec', alert:'med', cmd:t => `ike-scan ${t}` },
    { name:'Nikto', func:'5000+ peticiones buscando configs inseguros', alert:'high', cmd:t => `nikto -h ${t}` },
    { name:'sslscan', func:'Versiones TLS, cipher suites y certificados', alert:'med', cmd:t => `sslscan ${t}` },
    { name:'sslyze', func:'Análisis profundo TLS: ROBOT, Heartbleed', alert:'med', cmd:t => `sslyze ${t}` },
  ],
  amass: [
    { name:'intel', func:'Dominios por WHOIS inverso y ASNs', alert:'none', cmd:t => `amass intel -d ${t}` },
    { name:'enum -passive', func:'Subdominios solo con fuentes OSINT', alert:'none', cmd:t => `amass enum -passive -d ${t}` },
    { name:'enum -active', func:'Valida subdominios con DNS activo', alert:'low', cmd:t => `amass enum -active -d ${t}` },
    { name:'enum -brute', func:'Fuerza bruta DNS con resolvers públicos', alert:'med', cmd:t => `amass enum -brute -r 8.8.8.8,1.1.1.1 -dns-qps 30 -d ${t}` },
    { name:'track', func:'Nuevos subdominios vs escaneos anteriores', alert:'none', cmd:t => `amass track -d ${t}` },
    { name:'db', func:'Consulta base de datos local', alert:'none', cmd:t => `amass db -d ${t}` },
  ],
  katana: [
    { name:'Estático', func:'Rastrea HTML sin JS', alert:'low', cmd:t => `katana -u https://${t} -rl 20 -silent` },
    { name:'Con JS (-jc)', func:'Analiza .js buscando endpoints', alert:'low', cmd:t => `katana -u https://${t} -jc -rl 20 -silent` },
    { name:'Headless', func:'Chrome real para ejecutar JS', alert:'med', cmd:t => `katana -u https://${t} -headless -rl 15 -c 5 -no-sandbox` },
    { name:'robots + sitemap', func:'Lee robots.txt y sitemap.xml', alert:'low', cmd:t => `katana -u https://${t} -kf robotstxt,sitemapxml -rl 20 -silent` },
    { name:'Deep crawl', func:'Crawling profundo depth 5', alert:'med', cmd:t => `katana -u https://${t} -jc -kf robotstxt,sitemapxml -rl 10 -depth 5 -silent` },
    { name:'Con sesión', func:'Crawling autenticado con cookie', alert:'med', cmd:t => `katana -u https://${t} -H "Cookie: session=PEGAR_AQUI" -headless -rl 10` },
  ],
  gitleaks: [
    { name:'detect (dir)', func:'Escanea directorio local', alert:'none', cmd:_ => `gitleaks detect --source=. --report-format=json --report-path=gitleaks_report.json` },
    { name:'git (historial)', func:'Todo el historial de commits', alert:'none', cmd:_ => `gitleaks git --report-path=gitleaks_report.json .` },
    { name:'git (6 meses)', func:'Últimos 6 meses de commits', alert:'none', cmd:_ => `gitleaks git --log-opts="--since=6months" --report-path=gitleaks_report.json .` },
    { name:'git + ZIPs', func:'Incluye archivos comprimidos', alert:'none', cmd:_ => `gitleaks git --max-archive-depth=3 --report-path=gitleaks_report.json .` },
    { name:'Reglas custom', func:'Reglas TOML personalizadas', alert:'none', cmd:_ => `gitleaks git -c custom-rules.toml --report-path=gitleaks_report.json .` },
  ],
  wayback: [
    { name:'Básico', func:'Descarga todo lo archivado', alert:'none', cmd:t => `wayback_machine_downloader ${t} -d ./wayback_output -r 3` },
    { name:'Solo configs', func:'Filtra config y admin', alert:'none', cmd:t => `wayback_machine_downloader ${t} -d ./wayback_output -r 2 -p config -p admin --limit-pages 200` },
    { name:'Solo JS', func:'Solo ficheros .js', alert:'none', cmd:t => `wayback_machine_downloader ${t} -d ./wayback_output -r 2 -p .js --limit-pages 500` },
    { name:'Solo .env', func:'Ficheros .env y config expuestos', alert:'none', cmd:t => `wayback_machine_downloader ${t} -d ./wayback_output -r 2 -p .env -p .config` },
    { name:'Prefix limitado', func:'Descarga controlada con límite', alert:'none', cmd:t => `wayback_machine_downloader ${t} -d ./wayback_output -r 3 -m prefix --limit-pages 100` },
  ],
  spiderfoot: [
    { name:'Pasivo', func:'Solo fuentes pasivas', alert:'none', cmd:t => `spiderfoot -s ${t} -u passive -q` },
    { name:'Footprint', func:'Huella digital moderada', alert:'low', cmd:t => `spiderfoot -s ${t} -u footprint -q -max-threads 5` },
    { name:'DNS + WHOIS', func:'Solo DNS y WHOIS', alert:'none', cmd:t => `spiderfoot -s ${t} -m sfp_dns,sfp_dnsraw,sfp_whois -q` },
    { name:'Emails + HIBP', func:'Emails y brechas conocidas', alert:'none', cmd:t => `spiderfoot -s ${t} -m sfp_hunter,sfp_haveibeenpwned -q` },
    { name:'Shodan + Censys', func:'Infraestructura expuesta', alert:'none', cmd:t => `spiderfoot -s ${t} -m sfp_shodan,sfp_censys,sfp_alienvault -q` },
    { name:'Repos GitHub', func:'Repositorios GitHub del objetivo', alert:'none', cmd:t => `spiderfoot -s ${t} -m sfp_github -q` },
    { name:'Interfaz web', func:'UI completa en :5001', alert:'none', cmd:_ => `spiderfoot -l 127.0.0.1:5001` },
  ],
};

function alertBadge(a) {
  const map = {
    none:['al-none','Sin alerta'],
    low:['al-low','Baja'],
    med:['al-med','Media'],
    high:['al-high','Alta']
  };

  const [cls, txt] = map[a] || ['al-none', '—'];
  return `<span class="alert-badge ${cls}">${txt}</span>`;
}

const toolList = ['discover','amass','katana','gitleaks','wayback','spiderfoot'];

const toolMeta = {
  discover:{ title:'🔍 Discover', desc:'Framework orquestador.', tags:'<span class="tag tag-mit">MIT</span><span class="tag tag-npsl">Nmap NPSL</span>' },
  amass:{ title:'🌐 Amass', desc:'Subdominios con +55 fuentes.', tags:'<span class="tag tag-apache">Apache 2.0</span>' },
  katana:{ title:'🕷 Katana', desc:'Crawling web.', tags:'<span class="tag tag-mit">MIT</span>' },
  gitleaks:{ title:'🔑 GitLeaks', desc:'Secretos en repos Git.', tags:'<span class="tag tag-mit">MIT</span>' },
  wayback:{ title:'🕰 Wayback DL', desc:'Histórico archive.org.', tags:'<span class="tag tag-mit">MIT</span>' },
  spiderfoot:{ title:'🕸 SpiderFoot', desc:'200+ módulos OSINT.', tags:'<span class="tag tag-gpl">GPL v2</span>' },
};

const container = document.getElementById('tool-panels');

toolList.forEach(tool => {
  const m = toolMeta[tool];
  const ph = `
    <div class="panel" id="panel-${tool}">
      <div class="page-header">
        <div class="page-title">${m.title} ${m.tags}</div>
        <div class="page-desc">${m.desc}</div>
      </div>
      <div class="subtool-grid" id="sg-${tool}"></div>
      <div class="terminal-box" id="tb-${tool}" style="display:none">
        <div class="terminal-label">Terminal — edita o escribe cualquier comando</div>
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
        <div class="output-header"><span class="output-title">Resultados</span><button class="clr-btn" onclick="clearOut('${tool}')">Limpiar</button></div>
        <div class="out-tabs">
          <button class="out-tab active" onclick="switchTab('${tool}','parsed',this)">Resumen</button>
          <button class="out-tab" onclick="switchTab('${tool}','raw',this)">Output completo</button>
        </div>
        <div class="out-tab-content active" id="parsed-${tool}">
          <div class="results-area" id="results-${tool}">
            <p style="color:var(--text3);font-size:.8rem">Selecciona una subherramienta y pulsa Ejecutar.</p>
          </div>
        </div>
        <div class="out-tab-content" id="raw-${tool}">
          <div class="raw-output" id="raw-out-${tool}"></div>
        </div>
        <div class="status-bar">
          <div class="status-running" id="sr-${tool}"><div class="spinner"></div>Ejecutando...</div>
          <div class="status-done" id="sd-${tool}">✓ Completado</div>
          <span id="ss-${tool}">Listo</span>
        </div>
      </div>
    </div>
  `;
  container.insertAdjacentHTML('beforeend', ph);

  const grid = document.getElementById('sg-' + tool);
  SUBTOOLS[tool].forEach((s, i) => {
    const card = document.createElement('div');
    card.className = 'subtool-card';
    card.id = `card-${tool}-${i}`;
    card.innerHTML = `<div class="sc-top"><span class="sc-name">${s.name}</span>${alertBadge(s.alert)}</div><div class="sc-func">${s.func}</div>`;
    card.onclick = () => selectSubtool(tool, i, card);
    grid.appendChild(card);
  });
});

const pgrid = document.getElementById('parallel-subtool-grid');

toolList.forEach(tool => {
  const c = TOOL_COLORS[tool];
  const sec = document.createElement('div');
  sec.style.cssText = `background:var(--bg2);border:1.5px solid var(--border);border-radius:10px;overflow:hidden;`;
  sec.innerHTML = `
    <div style="padding:10px 14px;background:var(--bg3);border-bottom:1px solid var(--border);font-size:.75rem;font-weight:600;color:var(--text);display:flex;align-items:center;gap:8px;">
      <span style="background:${c.bg};color:${c.color};border:1px solid ${c.border};padding:2px 8px;border-radius:20px;font-size:.65rem;font-weight:700;">${tool.toUpperCase()}</span>
      ${toolMeta[tool].title.replace(/^.\s/,'')}
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;padding:12px;" id="psg-${tool}"></div>
  `;
  pgrid.appendChild(sec);

  SUBTOOLS[tool].forEach((s, i) => {
    const card = document.createElement('div');
    card.className = 'subtool-card';
    card.style.cssText = 'padding-left:32px;position:relative;';

    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.style.cssText = 'position:absolute;top:10px;left:10px;width:15px;height:15px;accent-color:#7c3aed;cursor:pointer;';
    cb.onchange = () => updateParallelCount();
    cb.dataset.tool = tool;
    cb.dataset.idx = i;

    card.appendChild(cb);
    card.insertAdjacentHTML('beforeend', `<div class="sc-top"><span class="sc-name">${s.name}</span>${alertBadge(s.alert)}</div><div class="sc-func">${s.func}</div>`);
    card.onclick = (e) => {
      if (e.target !== cb) {
        cb.checked = !cb.checked;
        updateParallelCount();
      }
    };

    document.getElementById('psg-' + tool).appendChild(card);
  });
});

function updateParallelCount() {
  const n = document.querySelectorAll('#parallel-subtool-grid input[type=checkbox]:checked').length;
  document.getElementById('parallel-count').textContent = n + ' seleccionada' + (n === 1 ? '' : 's');
  document.getElementById('launch-parallel-btn').disabled = n === 0;
}

const selectedSubtool = {};

function selectSubtool(tool, idx, card) {
  document.querySelectorAll(`#sg-${tool} .subtool-card`).forEach(c => c.classList.remove('selected'));
  card.classList.add('selected');
  selectedSubtool[tool] = idx;
  buildPreview(tool, idx);
}

function buildPreview(tool, idx) {
  const s = SUBTOOLS[tool][idx];
  const t = target || 'OBJETIVO';
  const fullCmd = s.cmd(t);
  const inp = document.getElementById('cmd-' + tool);
  const tb = document.getElementById('tb-' + tool);

  if (inp) {
    inp.value = fullCmd;
    tb.style.display = 'block';
  }
}

function switchTab(tool, tab, btn) {
  const sec = btn.closest('.output-section');
  sec.querySelectorAll('.out-tab').forEach(t => t.classList.remove('active'));
  sec.querySelectorAll('.out-tab-content').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');

  if (tab === 'parsed') {
    document.getElementById('parsed-' + tool).classList.add('active');
  } else {
    document.getElementById('raw-' + tool).classList.add('active');
  }
}

function parseOutput(tool, lines) {
  const groups = [];
  const joined = lines.join('\n');
  const isWhoisOutput = /Domain Name:|Registrar:|Name Server:|WHOIS/i.test(joined);

  if (['discover', 'amass', 'spiderfoot'].includes(tool)) {
    const emails = [...new Set(
      lines.flatMap(l => (l.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || []))
    )];
    if (emails.length) {
      groups.push({ title: 'Emails', icon: '✉️', type: 'email', items: emails });
    }

    let hosts = [...new Set(
      lines.flatMap(l => (l.match(/(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}/gi) || []))
        .map(h => h.trim().toLowerCase())
        .filter(h => !h.match(/^\d/) && h.split('.').length >= 2 && h.length > 5)
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
        .map(m => m[1].trim().toLowerCase());

      const domainMatch = joined.match(/Domain Name:\s*([^\n]+)/i);
      const mainDomain = domainMatch ? domainMatch[1].trim().toLowerCase() : null;

      hosts = hosts.filter(h => {
        if (noiseHosts.has(h)) return false;
        if (h.includes('http://') || h.includes('https://')) return false;
        if (h.includes('/')) return false;
        if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(h)) return false;
        if (h.split('.').some(part => !part || part.length > 63)) return false;
        return true;
      });

      hosts = hosts.filter(h => {
        return h === mainDomain || nsMatches.includes(h);
      });
    }

    if (hosts.length) {
      groups.push({ title: 'Hosts / Subdominios', icon: '🌐', type: 'host', items: hosts });
    }

    const ips = [...new Set(
      lines.flatMap(l => (l.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))
    )];
    if (ips.length) {
      groups.push({ title: 'IPs', icon: '📡', type: 'ip', items: ips });
    }
  }

  if (tool === 'discover') {
    const domainMatch =
      joined.match(/Domain Name:\s*([^\n]+)/i);

    const registrarMatch =
      joined.match(/Registrar:\s*([^\n]+)/i);

    const creationMatch =
      joined.match(/Creation Date:\s*([^\n]+)/i);

    const expiryMatch =
      joined.match(/Registry Expiry Date:\s*([^\n]+)/i) ||
      joined.match(/Registrar Registration Expiration Date:\s*([^\n]+)/i);

    const nsMatches = [...joined.matchAll(/Name Server:\s*([^\n]+)/gi)]
      .map(m => m[1].trim().toLowerCase());

    const statusMatches = [...joined.matchAll(/Domain Status:\s*([^\n]+)/gi)]
      .map(m => m[1].trim());

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
      lines.flatMap(l => (l.match(/https?:\/\/[^\s]+/g) || []))
    )];
    if (urls.length) {
      groups.push({ title: 'URLs encontradas', icon: '🔗', type: 'url', items: urls });
    }
  }

  if (tool === 'gitleaks') {
    const s = lines.filter(l => /(finding|secret|leak|RuleID|Match)/i.test(l));
    if (s.length) {
      groups.push({ title: 'Secretos detectados', icon: '🔑', type: 'generic', items: s });
    }
  }

  if (tool === 'wayback') {
    const f = lines.filter(l => /Downloading|Saved|\.(js|php|html|env|config|json)/i.test(l));
    if (f.length) {
      groups.push({ title: 'Archivos', icon: '📁', type: 'generic', items: f });
    }
  }

  const ports = lines.filter(l => /\d+\/(tcp|udp)\s+(open|closed|filtered)/i.test(l));
  if (ports.length) {
    groups.push({ title: 'Puertos', icon: '🔌', type: 'generic', items: ports });
  }

  return groups;
}

function renderParsed(tool, groups) {
  const el = document.getElementById('results-' + tool);

  if (!groups.length) {
    el.innerHTML = '<p style="color:var(--text3);font-size:.8rem">No se encontraron datos estructurados. Revisa el output completo.</p>';
    return;
  }

  el.innerHTML = groups.map(g => `
    <div class="result-group">
      <div class="rg-title">${g.icon} ${g.title} <span class="rg-count">${g.items.length}</span></div>
      <div class="result-items">
        ${g.items.map(i => `<div class="result-item ${g.type}">${escHtml(i)}</div>`).join('')}
      </div>
    </div>
  `).join('');
}

function runTool(tool) {
  const cmdEl = document.getElementById('cmd-' + tool);
  let cmd = cmdEl ? cmdEl.value.trim() : '';

  if (!cmd) {
    const idx = selectedSubtool[tool];
    if (idx === undefined) {
      document.getElementById('results-' + tool).innerHTML = '<p style="color:var(--red);font-size:.8rem">Selecciona una subherramienta o escribe un comando.</p>';
      return;
    }
    cmd = SUBTOOLS[tool][idx].cmd(target || 'OBJETIVO');
  }

  if (!target && tool !== 'gitleaks' && !cmd.includes(' ')) {
    document.getElementById('results-' + tool).innerHTML = '<p style="color:var(--red);font-size:.8rem">Introduce un dominio objetivo arriba.</p>';
    return;
  }

  const rawEl = document.getElementById('raw-out-' + tool);
  rawEl.textContent = '';
  setStatus(tool, 'running');
  document.getElementById('run-' + tool).disabled = true;
  document.getElementById('stop-' + tool).style.display = 'inline-block';
  document.getElementById('results-' + tool).innerHTML = '<p style="color:var(--text3);font-size:.8rem">Ejecutando...</p>';

  const allLines = [];

  streamCmd(cmd,(msg)=>{

  if(msg.startsWith('[START]')){
    rawEl.textContent += "▶ " + msg.replace('[START] ','') + "\n";
    rawEl.scrollTop = rawEl.scrollHeight;
    return;
  }

  if(msg.startsWith('[stderr]')){
    rawEl.textContent += "⚠ " + msg.replace('[stderr] ','') + "\n";
    rawEl.scrollTop = rawEl.scrollHeight;
    return;
  }

  if(msg.startsWith('[EXIT CODE]')){
    rawEl.textContent += "⚠ Process finished with code " + msg.replace('[EXIT CODE] ','') + "\n";
    return;
  }

  if(msg === '[DONE]'){
    setStatus(tool,'done');
    renderParsed(tool,parseOutput(tool,allLines));
    resetBtn(tool);
    return;
  }

  allLines.push(msg);
  rawEl.textContent += msg + "\n";
  rawEl.scrollTop = rawEl.scrollHeight;

  },(err)=>{
    document.getElementById('results-'+tool).innerHTML=
      `<p style="color:var(--red);font-size:.8rem">Error: ${err}</p>`;
    resetBtn(tool);
  });
}

function launchParallel() {
  const t = target || 'OBJETIVO';
  const checked = [...document.querySelectorAll('#parallel-subtool-grid input[type=checkbox]:checked')];
  if (!checked.length) return;

  const out = document.getElementById('parallel-out');
  out.innerHTML = '';
  document.getElementById('launch-parallel-btn').disabled = true;

  checked.forEach(cb => {
    const tool = cb.dataset.tool;
    const idx = parseInt(cb.dataset.idx);
    const s = SUBTOOLS[tool][idx];
    const cmd = s.cmd(t);
    const c = TOOL_COLORS[tool];

    appendParallelLine(tool, `▶ Iniciando: ${cmd}`, c, true);

    streamCmd(cmd, (msg) => {
      if (msg === '[DONE]') {
        appendParallelLine(tool, '✓ Completado', c, true);
      } else {
        appendParallelLine(tool, msg, c, false);
      }
    }, (err) => appendParallelLine(tool, '[ERROR] ' + err, c, false));
  });

  setTimeout(() => {
    document.getElementById('launch-parallel-btn').disabled = false;
  }, 1000);
}

function appendParallelLine(tool, msg, c, isHeader) {
  const out = document.getElementById('parallel-out');
  const div = document.createElement('div');
  div.className = 'pline';
  div.innerHTML = `<span class="ptag" style="background:${c.bg};color:${c.color};border:1px solid ${c.border}">${tool}</span><span class="ptext" style="${isHeader ? 'color:var(--text);font-weight:500' : ''}">${escHtml(msg)}</span>`;
  out.appendChild(div);
  out.scrollTop = out.scrollHeight;
}

function clearParallel() {
  document.querySelectorAll('#parallel-subtool-grid input[type=checkbox]').forEach(cb => cb.checked = false);
  updateParallelCount();
  document.getElementById('parallel-out').innerHTML = '<span style="color:var(--text3);font-size:.8rem">Selecciona herramientas arriba y pulsa Lanzar.</span>';
}

function goToPlan(tool, idx) {
  show(tool, null);
  const card = document.getElementById(`card-${tool}-${idx}`);
  if (card) {
    selectSubtool(tool, idx, card);
    card.scrollIntoView({ behavior:'smooth', block:'center' });
  }
}

function runPlanStep(cmdTemplate, tool) {
  const t = target || 'OBJETIVO';
  const cmd = cmdTemplate.replace(/OBJETIVO/g, t);
  show(tool, null);

  const rawEl = document.getElementById('raw-out-' + tool);
  if (rawEl) rawEl.textContent = '';

  setStatus(tool, 'running');
  if (document.getElementById('run-' + tool)) document.getElementById('run-' + tool).disabled = true;
  if (document.getElementById('stop-' + tool)) document.getElementById('stop-' + tool).style.display = 'inline-block';
  if (document.getElementById('results-' + tool)) document.getElementById('results-' + tool).innerHTML = '<p style="color:var(--text3);font-size:.8rem">Ejecutando desde plan...</p>';

  const inp = document.getElementById('cmd-' + tool);
  if (inp) {
    inp.value = cmd;
    document.getElementById('tb-' + tool).style.display = 'block';
  }

  const allLines = [];

  streamCmd(cmd, (msg) => {
    if (msg === '[DONE]') {
      setStatus(tool, 'done');
      renderParsed(tool, parseOutput(tool, allLines));
      resetBtn(tool);
    } else {
      allLines.push(msg);
      if (rawEl) {
        rawEl.textContent += msg + '\n';
        rawEl.scrollTop = rawEl.scrollHeight;
      }
    }
  }, (err) => {
    if (document.getElementById('results-' + tool)) {
      document.getElementById('results-' + tool).innerHTML = `<p style="color:var(--red);font-size:.8rem">Error: ${err}</p>`;
    }
    resetBtn(tool);
  });
}

function streamCmd(cmd, onData, onError) {
  fetch('/run', {
    method:'POST',
    headers:{ 'Content-Type':'application/json' },
    body:JSON.stringify({ cmd })
  })
  .then(res => {
    const reader = res.body.getReader();
    const dec = new TextDecoder();

    function read() {
      reader.read().then(({ done, value }) => {
        if (done) return;

        dec.decode(value).split('\n').forEach(line => {
          if (!line.startsWith('data:')) return;
          let msg;
          try {
            msg = JSON.parse(line.slice(5).trim());
          } catch {
            return;
          }
          onData(msg);
        });

        read();
      });
    }

    read();
  })
  .catch(e => onError(e.message));
}

function setStatus(tool, state) {
  document.getElementById('sr-' + tool).style.display = state === 'running' ? 'flex' : 'none';
  document.getElementById('sd-' + tool).style.display = state === 'done' ? 'inline' : 'none';
  const ss = document.getElementById('ss-' + tool);
  ss.style.display = state === 'running' || state === 'done' ? 'none' : 'inline';
}

function stopTool(tool) {
  resetBtn(tool);
  const ss = document.getElementById('ss-' + tool);
  document.getElementById('sr-' + tool).style.display = 'none';
  ss.style.display = 'inline';
  ss.textContent = 'Detenido';
}

function resetBtn(tool) {
  if (document.getElementById('run-' + tool)) document.getElementById('run-' + tool).disabled = false;
  if (document.getElementById('stop-' + tool)) document.getElementById('stop-' + tool).style.display = 'none';
}

function clearOut(tool) {
  document.getElementById('results-' + tool).innerHTML = '<p style="color:var(--text3);font-size:.8rem;padding:4px 0">Selecciona una subherramienta y pulsa Ejecutar.</p>';
  document.getElementById('raw-out-' + tool).textContent = '';
  setStatus(tool, 'idle');
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;');
}