'use strict';
// Surge Mac. All network probes explicitly use one named policy and no cookie jar.
const SOURCE = '🇺🇸USA';
const TARGET = '🏠Static Residential 🇺🇸';
const REPORT = 'usa-residential-report-v1';
const mode = typeof $argument === 'string' ? $argument : 'preview';

function api(method, path, body) {
  return new Promise((resolve, reject) => $httpAPI(method, path, body, result => {
    if (!result || result.error) reject(new Error('Surge API failed: ' + path));
    else resolve(result);
  }));
}

function get(policy, url) {
  return new Promise(resolve => {
    $httpClient.get({url, policy, timeout: 8, 'auto-cookie': false, 'auto-redirect': false},
      (error, response, body) => resolve(!error && response && response.status === 200 ? body : null));
  });
}

function parseJSON(body) {
  try { return JSON.parse(body); } catch (_) { return null; }
}

async function inspect({name, lineHash}) {
  const policy = lineHash || name;
  const row = {name, status: 'unknown'};
  const info = parseJSON(await get(policy, 'https://my.ippure.com/v1/info'));
  if (!info || !info.ip || !info.countryCode || typeof info.isResidential !== 'boolean') return row;
  row.country = info.countryCode;
  row.residential = info.isResidential;
  if (row.country !== 'US' || !row.residential) {
    row.status = 'excluded';
    return row;
  }
  const [openai, trace, gemini] = await Promise.all([
    get(policy, 'https://api.openai.com/compliance/cookie_requirements'),
    get(policy, 'https://claude.ai/cdn-cgi/trace'),
    get(policy, 'https://gemini.google.com/')
  ]);
  const consent = parseJSON(openai);
  row.chatgpt = !!consent && typeof consent.cookie_consent_required === 'boolean';
  row.claudeUS = /^loc=US\s*$/m.test(trace || '');
  row.geminiUS = /,2,1,200,"USA"/.test(gemini || '');
  row.status = row.chatgpt && row.claudeUS && row.geminiUS ? 'pass' : 'unconfirmed';
  return row;
}

function replacement(content, names) {
  const lines = content.split('\n');
  const indices = lines.map((line, idx) => line.split('=')[0].trim() === TARGET ? idx : -1).filter(idx => idx >= 0);
  if (indices.length !== 1) throw new Error('目标组缺失或重复');
  const i = indices[0];
  // Accept only the expected smart group with named options, no explicit members.
  const rhs = lines[i].slice(lines[i].indexOf('=') + 1);
  const fields = rhs.match(/(?:[^,"\n]|"[^"\n]*")+/g) || [];
  if (fields.shift()?.trim() !== 'smart' || fields.some(f => !/^\s*[\w-]+\s*=/.test(f))) throw new Error('目标组结构已变化');
  const keep = fields.filter(f => !/^\s*(include-other-group|include-all-proxies|policy-regex-filter)\s*=/.test(f));
  if (keep.some(f => /^\s*policy-path\s*=/.test(f))) throw new Error('目标组含独立订阅');
  // Encode delimiters as regex escapes so node names cannot change profile syntax.
  const literal = s => Array.from(s, c => /[a-zA-Z0-9\u0080-\u{10FFFF}]/u.test(c) ? c :
    Array.from({length:c.length}, (_,j) => '\\u' + c.charCodeAt(j).toString(16).padStart(4,'0')).join('')).join('');
  const filter = '^(?:' + names.map(literal).join('|') + ')$';
  lines[i] = TARGET + ' = smart, include-other-group="' + SOURCE + '", policy-regex-filter=' + filter + keep.map(f=>','+f).join('');
  return lines.join('\n');
}

function summary(r) {
  const passed = r.rows.filter(x=>x.status === 'pass').map(x=>x.name);
  const residential = r.rows.filter(x=>x.country === 'US' && x.residential).length;
  return [r.time, 'USA ' + r.rows.length + ' · 美国住宅 ' + residential + ' · 三项通过 ' + passed.length,
    '住宅属性未知 ' + r.rows.filter(x=>x.status === 'unknown').length, ...passed, r.note].join('\n');
}

async function run() {
  if (mode === 'panel') {
    const saved = parseJSON($persistentStore.read(REPORT));
    return {title:'AI Unlock Checker',content:saved ? summary(saved) : '请先运行 AI Unlock Scan 脚本'};
  }
  const sectionName = 'Proxy Group';
  const readSection = () => api('GET','/v1/profiles/section',{name:sectionName});
  const section = await readSection();
  const groups = await api('GET','/v1/policy_groups',{});
  if (!Array.isArray(groups[SOURCE]) || !groups[TARGET]) throw new Error('未找到来源组或目标组');
  const nodes = groups[SOURCE].filter(p=>p.enabled !== false && p.isGroup === false);
  if (new Set(nodes.map(p=>p.name)).size !== nodes.length) throw new Error('来源组有重名节点，无法按名称安全写回');
  if (!nodes.length) throw new Error('来源组没有可检测节点');
  const rows = Array(nodes.length);
  let cursor = 0;
  async function worker() {
    while (cursor < nodes.length) {
      const i = cursor++;
      rows[i] = await inspect(nodes[i]);
    }
  }
  await Promise.all(Array.from({length:Math.min(4,nodes.length)},worker));
  const passed = rows.filter(x=>x.status==='pass').map(x=>x.name);
  const report = {time:new Date().toISOString(),rows,note:'仅检测'};
  if (mode === 'apply') {
    if (!passed.length) report.note = '本轮零通过，保留原组';
    else {
      if (!section.editable || !section.revision) throw new Error('目标配置不可编辑');
      const content = replacement(section.content,passed);
      if (content !== section.content) {
        await api('POST','/v1/profiles/section',{name:sectionName,revision:section.revision,content});
        if ((await readSection()).content !== content) throw new Error('写后读回不一致');
      }
      report.note = '已核对目标配置';
    }
  }
  $persistentStore.write(JSON.stringify(report),REPORT);
  console.log('REPORT '+JSON.stringify(report));
  return {title:'AI Unlock Checker',content:summary(report)};
}
run().then($done).catch(error => {
  console.log('检测失败：'+error.message);
  $done({title:'AI Unlock Checker失败',content:error.message});
});
