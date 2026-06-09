# Rule-Hub

一个轻量级的 Clash 规则集 → Loon 规则集转换器，作为 Loon 插件内嵌使用。

## 功能特性

- 支持 Clash YAML 格式和纯文本格式规则集
- 自动检测输入格式
- 智能推断规则类型
- 实时转换预览
- 一键复制结果

## 项目结构

```
Rule-Hub/
├── assets/
│   └── icon.png                # 插件图标
├── modules/
│   ├── rule-hub.loon.plugin          # Loon 插件（正式版）
│   └── rule-hub.local.loon.plugin    # Loon 插件（局域网测试版）
├── src/
│   ├── clash-rules.js          # Clash 规则解析（CommonJS + 浏览器全局）
│   ├── loon-rules.js           # Loon 规则生成（CommonJS + 浏览器全局）
│   ├── converter.js            # 转换主逻辑（CommonJS + 浏览器全局）
│   ├── engine.js               # 构建生成的纯引擎代码（测试用）
│   ├── ui.js                   # 构建生成的 Loon 请求脚本
│   └── ui.html                 # HTML 模板
├── tests/
│   ├── clash-rules.test.js     # 解析器测试
│   ├── loon-rules.test.js      # 生成器测试
│   ├── converter.test.js       # 转换逻辑测试
│   └── build-output.test.js    # 构建产物运行时测试
├── build.js                    # 构建脚本
├── local-server.js             # 局域网测试服务器（自动更新 local 插件 IP）
├── package.json
├── README.md
└── CHANGELOG.md
```

## 快速开始

### 1. 安装 Loon 插件

将 `modules/rule-hub.loon.plugin` 导入到 Loon 应用中。

**插件说明：**
- **图标**: 使用 `assets/icon.png` 作为插件图标
- **脚本路径**: 插件中的 `script-path` 指向 GitHub raw URL，确保始终获取最新版本
- **域名**: 正式版使用 `rule.hub` 域名

### 2. 使用转换器

1. 在 Loon 中启用插件
2. 访问 `https://rule.hub`
3. 输入 Clash 规则集（URL 或文本）
4. 点击「转换」按钮
5. 复制转换结果或订阅链接

### 3. 局域网本地测试

适用于插件开发调试，脚本从本地服务器加载。

#### 启动步骤

1. 启动本地静态文件服务器：

```bash
cd Rule-Hub
node local-server.js
```

服务器默认监听 `0.0.0.0:8080`，可通过 `PORT` 环境变量修改端口。启动时自动检测本机 IP 并更新 local 插件中的地址。

2. 在 Loon 中导入 local 插件，访问 `https://rule.hub` 即可测试。

> 服务器启动时会自动检测本机局域网 IP 并更新 local 插件中的地址。

#### 正式版 vs 本地测试版

| 项目 | 正式版 | 本地测试版 |
|------|--------|-----------|
| 插件文件 | `rule-hub.loon.plugin` | `rule-hub.local.loon.plugin` |
| script-path | GitHub raw URL | 局域网 IP（如 `http://192.168.x.x:8080/src/ui.js`） |
| 用途 | 日常使用 | 开发调试 |

## 开发指南

### 核心模块

- **clash-rules.js**: 解析 Clash 规则集，输入清洗对齐原版 rule-parser.js
- **loon-rules.js**: 生成 Loon 规则集，过滤 Loon 不支持的规则类型
- **converter.js**: 组合两个模块，提供完整转换接口
- **ui.js**: Loon 请求脚本，通过 `$done({ response })` 返回完整 HTML 页面（所有逻辑内联）

### 规则类型映射

| Clash | Loon |
|-------|------|
| DOMAIN | DOMAIN |
| DOMAIN-SUFFIX | DOMAIN-SUFFIX |
| DOMAIN-KEYWORD | DOMAIN-KEYWORD |
| IP-CIDR | IP-CIDR |
| IP-CIDR6 | IP-CIDR6 |
| SRC-IP-CIDR | SRC-IP-CIDR |
| GEOIP | GEOIP |
| SRC-PORT | SRC-PORT |
| DST-PORT | DEST-PORT |
| MATCH | FINAL |

## 技术栈

- **前端**: 原生 HTML / CSS / JavaScript
- **后端**: JavaScript (Loon 脚本环境)
- **部署**: Loon 插件

## 测试与构建

```bash
npm install
npm test
node build.js    # 首次构建（生成 ui.js / engine.js）
npm run build    # 后续构建（会先自动跑测试）
```
