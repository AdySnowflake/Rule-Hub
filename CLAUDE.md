# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

Rule-Hub 是一个轻量级的 Clash 规则集 → Loon 规则集转换器，以 Loon 插件形式部署。生产环境运行在 Loon 脚本引擎中（非 Node.js），通过 MITM 域名 `rule.hub` 拦截请求。

## 常用命令

```bash
npm install          # 安装依赖（仅 jest）
npm test             # 运行测试（Jest）
node build.js        # 首次构建（生成 ui.js / engine.js，prebuild 测试需要产物已存在）
npm run build        # 后续构建（prebuild 自动先跑测试）
node local-server.js # 启动局域网开发服务器（默认 0.0.0.0:8080，PORT 环境变量可改）
```

运行单个测试文件：
```bash
npx jest tests/clash-rules.test.js
```

无 linter 配置（无 ESLint/Prettier）。

## 架构要点

### 双环境模块模式

三个核心源文件（`src/clash-rules.js`、`src/loon-rules.js`、`src/converter.js`）均采用双环境导出：
- 函数定义为全局函数（非模块化）
- 文件末尾通过 `typeof window` / `typeof module` 条件导出
- `// @BUILD:CUTOFF` 标记分隔核心逻辑与环境导出代码

**修改源文件时**：核心逻辑写在 `@BUILD:CUTOFF` 标记之上，环境导出代码写在标记之下。构建脚本只读取标记之前的内容。

### 构建流程（build.js）

构建脚本将三个源文件的核心逻辑（`@BUILD:CUTOFF` 之前）拼接为一个引擎 JS，然后与 HTML 模板合并生成两个产物：
- `src/ui.js` — 自包含的 Loon 请求脚本（生产产物，gitignored）
- `src/engine.js` — 纯引擎代码（供 VM 测试，gitignored）

`ui.js` 包含两条路由：
- `GET /` — 返回完整 HTML 页面（所有 CSS/JS 内联）
- `GET /convert?url=...` — 通过 `$httpClient.get()` 拉取远程规则并返回转换结果

### 测试策略

- `tests/clash-rules.test.js`、`loon-rules.test.js`、`converter.test.js` — 对源文件的单元/集成测试
- `tests/build-output.test.js` — 使用 Node `vm` 模块在沙箱中执行构建产物，模拟浏览器和 Loon 环境验证运行时正确性

### Loon 插件清单

- `modules/rule-hub.loon.plugin` — 正式版，script-path 指向 GitHub raw URL
- `modules/rule-hub.local.loon.plugin` — 本地测试版，`local-server.js` 启动时自动更新其中的 LAN IP

### 输入清洗管线

`clash-rules.js` 的解析器实现多阶段清洗：去 YAML 前缀 → 规范化注释 → 剥离内联注释 → 提取 `no-resolve` 标志 → 保护正则量词逗号 → 过滤脚本/元数据行 → 转换前缀表示法 → 智能类型推断。修改解析逻辑时需注意各阶段的顺序依赖。

## 注意事项

- `src/ui.js` 和 `src/engine.js` 是构建产物，不要手动编辑
- `src/ui.html` 是开发参考模板（使用 Vue 3 CDN），生产 UI 在 `build.js` 中以原生 JS 生成
- 文档语言为中文（README.md、TODO.md）

## 技术文档
- Loon: https://github.com/Loon0x00/LoonManual/tree/master/docs
- Mihomo: https://github.com/MetaCubeX/Meta-Docs
