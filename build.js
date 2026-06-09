/**
 * 构建脚本
 * 从同一份核心源码生成 src/ui.js（Loon 请求脚本）
 * 确保测试覆盖的是实际发布代码
 */

const fs = require('fs');
const path = require('path');
const pkg = require('./package.json');

const VERSION = pkg.version;
const UA = 'rule-hub/' + VERSION;

const SRC_DIR = path.join(__dirname, 'src');
const OUTPUT = path.join(SRC_DIR, 'ui.js');

/**
 * 读取源文件并截取 @BUILD:CUTOFF 之前的内容
 */
function readCoreLogic(filename) {
  const content = fs.readFileSync(path.join(SRC_DIR, filename), 'utf-8');
  const cutoff = content.indexOf('// @BUILD:CUTOFF');
  const core = cutoff >= 0 ? content.substring(0, cutoff) : content;
  return core.trim();
}

/**
 * 构建内联 JS 引擎（裸代码，不包裹 IIFE）
 * 函数在全局作用域，供 HTML UI 和 Loon 脚本 /convert 分支调用
 */
function buildEngineJS() {
  const clashRules = readCoreLogic('clash-rules.js');
  const loonRules = readCoreLogic('loon-rules.js');
  const converter = readCoreLogic('converter.js');

  // 简化 converter.js 中的环境兼容逻辑（函数已直接可用）
  const converterClean = converter
    .replace(/const _parseClashRules = typeof parseClashRules[\s\S]*?require\([^)]+\)[^;]*;/g,
      'const _parseClashRules = parseClashRules;')
    .replace(/const _generateLoonRules = typeof generateLoonRules[\s\S]*?require\([^)]+\)[^;]*;/g,
      'const _generateLoonRules = generateLoonRules;');

  return `${clashRules}\n\n${loonRules}\n\n${converterClean}\n`;
}

/**
 * 构建完整 HTML 页面（无 Vue 依赖）
 */
function buildHTML(engineJS) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Rule-Hub</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,Cantarell,'Open Sans','Helvetica Neue',sans-serif;line-height:1.6;color:#333;background:#f5f5f5;min-height:100vh}
    .container{max-width:900px;margin:0 auto;padding:20px}
    header{text-align:center;margin-bottom:30px}
    header h1{font-size:24px;color:#2c3e50;margin-bottom:8px}
    header p{color:#666;font-size:14px}
    .card{background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);padding:20px;margin-bottom:20px}
    .card-title{font-size:16px;font-weight:600;color:#2c3e50;margin-bottom:15px;padding-bottom:10px;border-bottom:1px solid #eee}
    .mode-switch{display:flex;gap:10px;margin-bottom:15px}
    .mode-btn{flex:1;padding:10px 16px;border:2px solid #e0e0e0;border-radius:6px;background:#fff;color:#666;font-size:14px;cursor:pointer;transition:all .2s}
    .mode-btn:hover{border-color:#3498db;color:#3498db}
    .mode-btn.active{border-color:#3498db;background:#3498db;color:#fff}
    .input-area{margin-bottom:15px}
    .input-area label{display:block;font-size:14px;color:#555;margin-bottom:8px}
    .input-area input[type="text"],.input-area textarea{width:100%;padding:12px;border:1px solid #ddd;border-radius:6px;font-size:14px;font-family:'Monaco','Menlo','Ubuntu Mono',monospace;transition:border-color .2s}
    .input-area input[type="text"]:focus,.input-area textarea:focus{outline:none;border-color:#3498db;box-shadow:0 0 0 3px rgba(52,152,219,.1)}
    .input-area textarea{min-height:200px;resize:vertical}
    .actions{display:flex;gap:10px;margin-bottom:15px}
    .btn{padding:10px 20px;border:none;border-radius:6px;font-size:14px;font-weight:500;cursor:pointer;transition:all .2s}
    .btn:disabled{opacity:.5;cursor:not-allowed}
    .btn-primary{background:#3498db;color:#fff}
    .btn-primary:hover:not(:disabled){background:#2980b9}
    .btn-secondary{background:#95a5a6;color:#fff}
    .btn-secondary:hover:not(:disabled){background:#7f8c8d}
    .btn-success{background:#27ae60;color:#fff}
    .btn-success:hover:not(:disabled){background:#229954}
    .loading{display:flex;align-items:center;justify-content:center;gap:10px;padding:20px;color:#666}
    .spinner{width:20px;height:20px;border:2px solid #e0e0e0;border-top-color:#3498db;border-radius:50%;animation:spin .8s linear infinite}
    @keyframes spin{to{transform:rotate(360deg)}}
    .error{background:#fee;border:1px solid #fcc;border-radius:6px;padding:12px;margin-bottom:15px;color:#c00;font-size:14px;display:flex;justify-content:space-between;align-items:center}
    .error-close{background:none;border:none;color:#c00;cursor:pointer;font-size:18px;padding:0 5px}
    .stats{display:flex;gap:20px;flex-wrap:wrap;margin-bottom:15px;padding:12px;background:#f8f9fa;border-radius:6px}
    .stat-item{font-size:13px;color:#666}
    .stat-item span{font-weight:600;color:#333}
    .output-area textarea{width:100%;min-height:200px;padding:12px;border:1px solid #ddd;border-radius:6px;font-size:14px;font-family:'Monaco','Menlo','Ubuntu Mono',monospace;background:#f8f9fa;resize:vertical}
    .output-actions{display:flex;gap:10px;margin-top:10px}
    .toast{position:fixed;top:20px;right:20px;background:#333;color:#fff;padding:12px 20px;border-radius:6px;font-size:14px;z-index:1000;animation:fadeInOut 2s ease-in-out}
    @keyframes fadeInOut{0%{opacity:0;transform:translateY(-10px)}15%{opacity:1;transform:translateY(0)}85%{opacity:1;transform:translateY(0)}100%{opacity:0;transform:translateY(-10px)}}
    @media(max-width:600px){.container{padding:10px}.mode-switch{flex-direction:column}.actions{flex-direction:column}.btn{width:100%}.stats{flex-direction:column;gap:8px}}
  </style>
</head>
<body>
  <div id="app">
    <div class="container">
      <header>
        <h1>Rule-Hub</h1>
        <p>将 Clash 规则集转换为 Loon 规则集</p>
      </header>
      <div class="card">
        <div class="card-title">输入规则</div>
        <div class="mode-switch">
          <button class="mode-btn active" data-mode="url" onclick="switchMode('url')">URL 获取</button>
          <button class="mode-btn" data-mode="text" onclick="switchMode('text')">粘贴文本</button>
        </div>
        <div id="url-input" class="input-area">
          <label>规则集 URL</label>
          <input type="text" id="inputUrl" placeholder="https://example.com/rules.yaml">
        </div>
        <div id="text-input" class="input-area" style="display:none">
          <label>Clash 规则集</label>
          <textarea id="inputText" placeholder="粘贴 Clash 规则集内容..."></textarea>
        </div>
        <div class="actions">
          <button class="btn btn-primary" id="convertBtn" onclick="doConvert()">开始转换</button>
          <button class="btn btn-secondary" onclick="doClear()">清空</button>
        </div>
      </div>
      <div id="error-box" class="error" style="display:none">
        <span id="error-msg"></span>
        <button class="error-close" onclick="hideError()">&times;</button>
      </div>
      <div id="loading" class="loading" style="display:none">
        <div class="spinner"></div>
        <span>正在转换...</span>
      </div>
      <div id="output-card" class="card" style="display:none">
        <div class="card-title">转换结果</div>
        <div id="stats" class="stats" style="display:none">
          <div class="stat-item">原始规则: <span id="stat-original">0</span></div>
          <div class="stat-item">转换成功: <span id="stat-converted">0</span></div>
          <div class="stat-item">不支持: <span id="stat-unsupported">0</span></div>
        </div>
        <div class="output-area">
          <textarea id="outputText" readonly></textarea>
        </div>
        <div class="output-actions">
          <button class="btn btn-success" onclick="doCopy()">复制结果</button>
          <button class="btn btn-primary" id="copyLinkBtn" onclick="doCopyLink()" style="display:none">复制链接</button>
        </div>
      </div>
    </div>
    <div id="toast" class="toast" style="display:none"></div>
  </div>
  <script>
  var RULE_HUB_UA = '${UA}';
  ${engineJS}

  // === 原生 JS UI 逻辑 ===
  var inputMode = 'url';

  function switchMode(mode) {
    inputMode = mode;
    var btns = document.querySelectorAll('.mode-btn');
    for (var i = 0; i < btns.length; i++) {
      btns[i].classList.toggle('active', btns[i].getAttribute('data-mode') === mode);
    }
    document.getElementById('url-input').style.display = mode === 'url' ? '' : 'none';
    document.getElementById('text-input').style.display = mode === 'text' ? '' : 'none';
  }

  function showError(msg) {
    document.getElementById('error-msg').textContent = msg;
    document.getElementById('error-box').style.display = '';
  }

  function hideError() {
    document.getElementById('error-box').style.display = 'none';
  }

  function showToast(msg) {
    var el = document.getElementById('toast');
    el.textContent = msg;
    el.style.display = '';
    setTimeout(function() { el.style.display = 'none'; }, 2000);
  }

  function setLoading(on) {
    document.getElementById('loading').style.display = on ? '' : 'none';
    document.getElementById('convertBtn').disabled = on;
    document.getElementById('convertBtn').textContent = on ? '转换中...' : '开始转换';
  }

  function showResult(result) {
    var stats = parseStats(result);
    document.getElementById('stat-original').textContent = stats.originalCount;
    document.getElementById('stat-converted').textContent = stats.convertedCount;
    document.getElementById('stat-unsupported').textContent = stats.unsupportedCount;
    document.getElementById('stats').style.display = '';
    document.getElementById('outputText').value = result;
    document.getElementById('output-card').style.display = '';
    document.getElementById('copyLinkBtn').style.display = inputMode === 'url' ? '' : 'none';
  }

  function doConvert() {
    hideError();
    document.getElementById('output-card').style.display = 'none';
    setLoading(true);

    if (inputMode === 'url') {
      var url = document.getElementById('inputUrl').value.trim();
      if (!url) { showError('请输入 URL'); setLoading(false); return; }
      // 通过 /convert 端点由脚本侧拉取（避免 CORS）
      fetch('/convert?url=' + encodeURIComponent(url), { headers: { 'User-Agent': RULE_HUB_UA } })
        .then(function(r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.text();
        })
        .then(function(text) { showResult(text); })
        .catch(function(e) { showError('获取失败: ' + e.message); })
        .finally(function() { setLoading(false); });
    } else {
      var text = document.getElementById('inputText').value.trim();
      if (!text) { showError('请输入规则集'); setLoading(false); return; }
      try {
        var result = convertClashToLoon(text);
        showResult(result);
      } catch (e) {
        showError(e.message);
      }
      setLoading(false);
    }
  }

  function doCopy() {
    var text = document.getElementById('outputText').value;
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(function() { showToast('已复制到剪贴板'); });
    } else {
      var ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showToast('已复制到剪贴板');
    }
  }

  function doCopyLink() {
    var url = document.getElementById('inputUrl').value.trim();
    if (!url) { showToast('无可用链接'); return; }
    var link = location.origin + '/convert?url=' + encodeURIComponent(url);
    if (navigator.clipboard) {
      navigator.clipboard.writeText(link).then(function() { showToast('链接已复制到剪贴板'); });
    } else {
      var ta = document.createElement('textarea');
      ta.value = link;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showToast('链接已复制到剪贴板');
    }
  }

  function doClear() {
    document.getElementById('inputUrl').value = '';
    document.getElementById('inputText').value = '';
    document.getElementById('output-card').style.display = 'none';
    document.getElementById('copyLinkBtn').style.display = 'none';
    hideError();
  }
  <\/script>
</body>
</html>`;
}

/**
 * 构建 Loon 请求脚本 ui.js
 */
function build() {
  console.log('Building ui.js ...');

  const engineJS = buildEngineJS();
  const html = buildHTML(engineJS);

  const script = `/**
 * Loon 请求脚本 — Rule-Hub
 * 由 build.js 自动生成，请勿手动编辑
 *
 * - GET /            → 返回 HTML 页面
 * - GET /convert?url= → 拉取远程规则并返回转换结果
 */

// === 核心转换引擎（顶层作用域，供 /convert 分支调用）===
${engineJS}

var url = $request.url;

if (url.match(/\\/convert(\\?|$)/)) {
  // === 转换接口 ===
  var sourceUrl = (url.match(/[?&]url=([^&]+)/) || [])[1] || '';
  if (!sourceUrl) {
    $done({ response: { status: 400, body: 'Missing url parameter', headers: { 'Content-Type': 'text/plain' } } });
  } else {
    sourceUrl = decodeURIComponent(sourceUrl);
    $httpClient.get({ url: sourceUrl, headers: { 'User-Agent': '${UA}' } }, function(err, resp, data) {
      if (err || resp.status !== 200) {
        $done({ response: { status: 502, body: 'Failed to fetch: ' + (err || resp.status), headers: { 'Content-Type': 'text/plain' } } });
        return;
      }
      try {
        var result = convertClashToLoon(data);
        $done({ response: { status: 200, body: result, headers: { 'Content-Type': 'text/plain; charset=utf-8' } } });
      } catch (e) {
        $done({ response: { status: 422, body: 'Convert error: ' + e.message, headers: { 'Content-Type': 'text/plain' } } });
      }
    });
  }
} else {
  // === HTML 页面 ===
  $done({
    response: {
      status: 200,
      body: ${JSON.stringify(html)},
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      }
    }
  });
}
`;

  // 写入 ui.js（Loon 请求脚本）
  fs.writeFileSync(OUTPUT, script, 'utf-8');
  console.log('Done: ' + OUTPUT);

  // 写入 engine.js（纯引擎代码，供 VM 测试使用）
  const enginePath = path.join(SRC_DIR, 'engine.js');
  fs.writeFileSync(enginePath, engineJS, 'utf-8');
  console.log('Done: ' + enginePath);
}

build();
