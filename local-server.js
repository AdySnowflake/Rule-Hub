const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const root = __dirname;
const host = '0.0.0.0';
const port = Number(process.env.PORT || 8080);

// 自动检测局域网 IP 并更新 local 插件
let lanIP = null;

function updateLocalPluginIP() {
  const interfaces = os.networkInterfaces();
  for (const iface of Object.values(interfaces)) {
    for (const info of iface) {
      if (info.family === 'IPv4' && !info.internal) {
        lanIP = info.address;
        break;
      }
    }
    if (lanIP) break;
  }
  if (!lanIP) return;

  const pluginPath = path.join(__dirname, 'modules', 'rule-hub.local.loon.plugin');
  if (!fs.existsSync(pluginPath)) return;

  let content = fs.readFileSync(pluginPath, 'utf-8');
  content = content.replace(/http:\/\/[\d.]+:\d+/g, `http://${lanIP}:${port}`);
  fs.writeFileSync(pluginPath, content, 'utf-8');
}

updateLocalPluginIP();

const types = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.plugin': 'text/plain; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8'
};

function send(res, status, body, headers = {}) {
  res.writeHead(status, headers);
  res.end(body);
}

http.createServer((req, res) => {
  const urlPath = decodeURIComponent((req.url || '/').split('?')[0]);
  const relativePath = urlPath === '/' ? 'README.md' : urlPath.replace(/^\/+/, '');
  const filePath = path.resolve(root, relativePath);

  if (!filePath.startsWith(root + path.sep) && filePath !== root) {
    send(res, 403, 'Forbidden', { 'Content-Type': 'text/plain; charset=utf-8' });
    return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      send(res, 404, 'Not found', { 'Content-Type': 'text/plain; charset=utf-8' });
      return;
    }

    send(res, 200, data, {
      'Content-Type': types[path.extname(filePath)] || 'application/octet-stream'
    });
  });
}).listen(port, host, () => {
  console.log(`Rule-Hub local server: http://localhost:${port}`);
  if (lanIP) {
    console.log(`Loon plugin: http://${lanIP}:${port}/modules/rule-hub.local.loon.plugin`);
  }
});
