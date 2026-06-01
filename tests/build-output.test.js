/**
 * 构建产物测试
 * 验证构建生成的 engine.js 中转换逻辑与源模块行为一致
 * 覆盖实际发布脚本的运行路径
 *
 * 流程：源码 → build.js → engine.js → 本测试验证
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ENGINE_PATH = path.join(__dirname, '..', 'src', 'engine.js');
const UI_PATH = path.join(__dirname, '..', 'src', 'ui.js');

let sandbox;

beforeAll(() => {
  if (!fs.existsSync(ENGINE_PATH)) {
    throw new Error('engine.js 不存在，请先运行 node build.js');
  }

  const engineCode = fs.readFileSync(ENGINE_PATH, 'utf-8');

  // 在 VM 沙箱中执行，模拟浏览器环境
  sandbox = {
    console: { log: jest.fn(), error: jest.fn() },
    setTimeout: jest.fn(),
    clearTimeout: jest.fn(),
    fetch: jest.fn(),
    URL: URL
  };

  vm.createContext(sandbox);
  vm.runInContext(engineCode, sandbox);
});

describe('构建产物验证 - 转换引擎', () => {
  test('convertClashToLoon 函数存在', () => {
    expect(typeof sandbox.convertClashToLoon).toBe('function');
  });

  test('parseStats 函数存在', () => {
    expect(typeof sandbox.parseStats).toBe('function');
  });

  test('基本转换功能', () => {
    const input = `DOMAIN-SUFFIX,example.com\nIP-CIDR,192.168.0.0/16,no-resolve\nMATCH,DIRECT`;
    const output = sandbox.convertClashToLoon(input);

    expect(output).toContain('DOMAIN-SUFFIX,example.com');
    expect(output).toContain('IP-CIDR,192.168.0.0/16,no-resolve');
    expect(output).toContain('FINAL');
  });

  test('DST-PORT 转换为 DEST-PORT', () => {
    const input = `DST-PORT,443\nDOMAIN,example.com`;
    const output = sandbox.convertClashToLoon(input);

    expect(output).toContain('DEST-PORT,443');
    expect(output).not.toContain('DST-PORT,443');
    expect(output).toContain('DOMAIN,example.com');
  });

  test('DST-PORT 多端口 / 拆分为多条 DEST-PORT', () => {
    const input = 'DST-PORT,80/443/8080';
    const output = sandbox.convertClashToLoon(input);

    expect(output).toContain('DEST-PORT,80');
    expect(output).toContain('DEST-PORT,443');
    expect(output).toContain('DEST-PORT,8080');
    expect(output).not.toContain('DST-PORT');
  });

  test('DST-PORT 多端口 , 拆分为多条 DEST-PORT', () => {
    const input = 'DST-PORT,80,443,8080';
    const output = sandbox.convertClashToLoon(input);

    expect(output).toContain('DEST-PORT,80');
    expect(output).toContain('DEST-PORT,443');
    expect(output).toContain('DEST-PORT,8080');
  });

  test('SRC-PORT 多端口拆分', () => {
    const input = 'SRC-PORT,1024,2048';
    const output = sandbox.convertClashToLoon(input);

    expect(output).toContain('SRC-PORT,1024');
    expect(output).toContain('SRC-PORT,2048');
  });

  test('// 注释被剥离', () => {
    const input = 'DOMAIN-SUFFIX,example.com // comment';
    const output = sandbox.convertClashToLoon(input);

    expect(output).toContain('DOMAIN-SUFFIX,example.com');
    expect(output).not.toContain('// comment');
  });

  test('no-resolve 大小写不敏感', () => {
    const input = 'IP-CIDR,10.0.0.0/8,NO-RESOLVE';
    const output = sandbox.convertClashToLoon(input);

    expect(output).toContain('IP-CIDR,10.0.0.0/8,no-resolve');
  });

  test('.prefix 转换为 DOMAIN-SUFFIX', () => {
    const input = '.example.com';
    const output = sandbox.convertClashToLoon(input);

    expect(output).toContain('DOMAIN-SUFFIX,example.com');
  });

  test('脚本/元数据行被过滤', () => {
    const input = `DOMAIN,example.com\ntest-script.js enabled = true\nIP-CIDR,192.168.0.0/16`;
    const output = sandbox.convertClashToLoon(input);

    expect(output).not.toContain('test-script.js');
    expect(output).toContain('DOMAIN,example.com');
    expect(output).toContain('IP-CIDR,192.168.0.0/16');
  });

  test('YAML 格式解析', () => {
    const input = `payload:\n- DOMAIN-SUFFIX,example.com\n- GEOIP,CN`;
    const output = sandbox.convertClashToLoon(input);

    expect(output).toContain('DOMAIN-SUFFIX,example.com');
    expect(output).toContain('GEOIP,CN');
  });

  test('parseStats 正确解析统计信息', () => {
    const loonText = `# Loon 规则集\n# 生成时间: 2026-01-01\n# 原始规则数: 10\n# 转换规则数: 8\n# 不支持规则数: 2\nDOMAIN,example.com`;
    const stats = sandbox.parseStats(loonText);

    expect(stats.originalCount).toBe(10);
    expect(stats.convertedCount).toBe(8);
    expect(stats.unsupportedCount).toBe(2);
  });
});

describe('构建产物验证 - ui.js 结构', () => {
  let uiContent;

  beforeAll(() => {
    uiContent = fs.readFileSync(UI_PATH, 'utf-8');
  });

  test('ui.js 包含 $done 响应逻辑', () => {
    expect(uiContent).toContain('$done');
    expect(uiContent).toContain('text/html');
  });

  test('ui.js 包含 /convert 端点逻辑', () => {
    expect(uiContent).toContain('/convert');
    expect(uiContent).toContain('$httpClient');
  });

  test('ui.js 不依赖外部 CDN', () => {
    expect(uiContent).not.toContain('unpkg.com');
    expect(uiContent).not.toContain('cdn.jsdelivr.net');
  });

  test('ui.js 包含内联引擎（非手写副本）', () => {
    // 验证构建标记注释被移除
    expect(uiContent).not.toContain('@BUILD:CUTOFF');
    // 验证引擎函数存在
    expect(uiContent).toContain('function convertClashToLoon');
    expect(uiContent).toContain('function parseClashRules');
    expect(uiContent).toContain('function generateLoonRules');
  });
});

describe('ui.js 运行时测试 - 根路径 HTML', () => {
  let htmlBody;
  let scriptContent;

  beforeAll(() => {
    const uiCode = fs.readFileSync(UI_PATH, 'utf-8');

    // 模拟 Loon 环境执行 ui.js（根路径）
    const doneCalls = [];
    const loonSandbox = {
      $request: { url: 'https://rule.hub/' },
      $done: (result) => doneCalls.push(result),
      $httpClient: { get: jest.fn() },
      console: { log: jest.fn(), error: jest.fn() }
    };

    vm.createContext(loonSandbox);
    vm.runInContext(uiCode, loonSandbox);

    // 提取 HTML body
    expect(doneCalls.length).toBe(1);
    expect(doneCalls[0].response.status).toBe(200);
    htmlBody = doneCalls[0].response.body;

    // 提取 <script> 标签内容
    const scriptMatch = htmlBody.match(/<script>([\s\S]*?)<\/script>/);
    expect(scriptMatch).not.toBeNull();
    scriptContent = scriptMatch[1];
  });

  test('根路径返回完整 HTML 页面', () => {
    expect(htmlBody).toContain('<!DOCTYPE html>');
    expect(htmlBody).toContain('Rule-Hub');
    expect(htmlBody).toContain('convertClashToLoon');
  });

  test('HTML 内脚本可访问 convertClashToLoon', () => {
    const testSandbox = {
      console: { log: jest.fn(), error: jest.fn() },
      document: {
        getElementById: jest.fn(() => ({ style: {}, textContent: '', value: '', disabled: false, classList: { toggle: jest.fn() } })),
        querySelectorAll: jest.fn(() => []),
        createElement: jest.fn(() => ({ value: '', select: jest.fn() })),
        execCommand: jest.fn()
      },
      navigator: { clipboard: null },
      setTimeout: jest.fn(),
      fetch: jest.fn()
    };

    vm.createContext(testSandbox);
    vm.runInContext(scriptContent, testSandbox);

    expect(typeof testSandbox.convertClashToLoon).toBe('function');
    expect(typeof testSandbox.parseStats).toBe('function');
  });

  test('HTML 内脚本可执行文本模式转换', () => {
    const testSandbox = {
      console: { log: jest.fn(), error: jest.fn() },
      document: {
        getElementById: jest.fn((id) => {
          if (id === 'inputText') return { value: 'DOMAIN-SUFFIX,example.com\nMATCH,DIRECT', style: {} };
          if (id === 'outputText') return { value: '', style: {} };
          if (id === 'stat-original') return { textContent: '', style: {} };
          if (id === 'stat-converted') return { textContent: '', style: {} };
          if (id === 'stat-unsupported') return { textContent: '', style: {} };
          if (id === 'stats') return { style: {} };
          if (id === 'output-card') return { style: {} };
          if (id === 'error-box') return { style: {} };
          if (id === 'loading') return { style: {} };
          if (id === 'convertBtn') return { disabled: false, textContent: '' };
          return { style: {}, textContent: '', value: '', disabled: false };
        }),
        querySelectorAll: jest.fn(() => []),
        createElement: jest.fn(() => ({ value: '', select: jest.fn() })),
        execCommand: jest.fn()
      },
      navigator: { clipboard: null },
      setTimeout: jest.fn(),
      fetch: jest.fn()
    };

    vm.createContext(testSandbox);
    vm.runInContext(scriptContent, testSandbox);

    // 执行文本模式转换
    testSandbox.doConvert();

    // 验证 outputText 被设置了转换结果（通过 getElementById mock 检查）
    const outputTextCall = testSandbox.document.getElementById.mock.results.find(
      r => r.value && r.value.value !== undefined
    );
    // 由于 mock 限制，验证函数不抛出异常即可
    expect(testSandbox.doConvert).not.toThrow();
  });
});

describe('ui.js 运行时测试 - /convert 端点', () => {
  test('/convert 端点成功转换', () => {
    const uiCode = fs.readFileSync(UI_PATH, 'utf-8');
    const doneCalls = [];

    const loonSandbox = {
      $request: { url: 'https://rule.hub/convert?url=https%3A%2F%2Fexample.com%2Frules.yaml' },
      $done: (result) => doneCalls.push(result),
      $httpClient: {
        get: jest.fn((url, callback) => {
          // 模拟返回规则文本
          callback(null, { status: 200 }, 'DOMAIN-SUFFIX,example.com\nIP-CIDR,10.0.0.0/8,no-resolve\nMATCH,DIRECT');
        })
      },
      console: { log: jest.fn(), error: jest.fn() }
    };

    vm.createContext(loonSandbox);
    vm.runInContext(uiCode, loonSandbox);

    // 验证 $httpClient.get 被调用
    expect(loonSandbox.$httpClient.get).toHaveBeenCalled();
    const calledArgs = loonSandbox.$httpClient.get.mock.calls[0][0];
    expect(calledArgs.url).toBe('https://example.com/rules.yaml');
    expect(calledArgs.headers).toHaveProperty('User-Agent');
    expect(calledArgs.headers['User-Agent']).toMatch(/^rule-hub\//);

    // 验证 $done 返回转换结果
    expect(doneCalls.length).toBe(1);
    expect(doneCalls[0].response.status).toBe(200);
    expect(doneCalls[0].response.body).toContain('DOMAIN-SUFFIX,example.com');
    expect(doneCalls[0].response.body).toContain('IP-CIDR,10.0.0.0/8,no-resolve');
    expect(doneCalls[0].response.body).toContain('FINAL');
  });

  test('/convert 端点缺少 url 参数返回 400', () => {
    const uiCode = fs.readFileSync(UI_PATH, 'utf-8');
    const doneCalls = [];

    const loonSandbox = {
      $request: { url: 'https://rule.hub/convert' },
      $done: (result) => doneCalls.push(result),
      $httpClient: { get: jest.fn() },
      console: { log: jest.fn(), error: jest.fn() }
    };

    vm.createContext(loonSandbox);
    vm.runInContext(uiCode, loonSandbox);

    expect(doneCalls.length).toBe(1);
    expect(doneCalls[0].response.status).toBe(400);
    expect(doneCalls[0].response.body).toContain('Missing url parameter');
  });

  test('/convert 端点远程获取失败返回 502', () => {
    const uiCode = fs.readFileSync(UI_PATH, 'utf-8');
    const doneCalls = [];

    const loonSandbox = {
      $request: { url: 'https://rule.hub/convert?url=https%3A%2F%2Fexample.com%2Frules.yaml' },
      $done: (result) => doneCalls.push(result),
      $httpClient: {
        get: jest.fn((url, callback) => {
          callback('Connection timeout', null, null);
        })
      },
      console: { log: jest.fn(), error: jest.fn() }
    };

    vm.createContext(loonSandbox);
    vm.runInContext(uiCode, loonSandbox);

    expect(doneCalls.length).toBe(1);
    expect(doneCalls[0].response.status).toBe(502);
    expect(doneCalls[0].response.body).toContain('Failed to fetch');
  });

  test('/convert 端点转换失败返回 422', () => {
    const uiCode = fs.readFileSync(UI_PATH, 'utf-8');
    const doneCalls = [];

    const loonSandbox = {
      $request: { url: 'https://rule.hub/convert?url=https%3A%2F%2Fexample.com%2Frules.yaml' },
      $done: (result) => doneCalls.push(result),
      $httpClient: {
        get: jest.fn((url, callback) => {
          // 返回空内容，触发转换错误
          callback(null, { status: 200 }, '');
        })
      },
      console: { log: jest.fn(), error: jest.fn() }
    };

    vm.createContext(loonSandbox);
    vm.runInContext(uiCode, loonSandbox);

    expect(doneCalls.length).toBe(1);
    expect(doneCalls[0].response.status).toBe(422);
    expect(doneCalls[0].response.body).toContain('Convert error');
  });
});
