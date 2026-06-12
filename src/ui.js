/**
 * Loon 请求脚本 — Rule-Hub
 * 由 build.js 自动生成，请勿手动编辑
 *
 * - GET /            → 返回 HTML 页面
 * - GET /convert?url= → 拉取远程规则并返回转换结果
 */

// === 核心转换引擎（顶层作用域，供 /convert 分支调用）===
/**
 * Clash 规则解析器
 * 支持 YAML 格式和纯文本格式的 Clash 规则集解析
 * 输入清洗逻辑对齐原版 rule-parser.js
 */

// 支持的规则类型
const SUPPORTED_TYPES = [
  'DOMAIN',
  'DOMAIN-SUFFIX',
  'DOMAIN-KEYWORD',
  'IP-CIDR',
  'IP-CIDR6',
  'SRC-IP-CIDR',
  'GEOIP',
  'SRC-PORT',
  'DST-PORT',
  'NETWORK',
  'MATCH',
  'AND',
  'OR',
  'NOT'
];

// 正则量词逗号保护占位符（与原版 t&zd; 一致）
const COMMA_PLACEHOLDER = 't&zd;';

/**
 * 检测规则集格式
 * @param {string} text - 规则集文本
 * @returns {'yaml'|'plain'} 格式类型
 */
function detectFormat(text) {
  const lines = text.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed.startsWith('payload:')) {
      return 'yaml';
    }

    if (trimmed.startsWith('- ')) {
      return 'yaml';
    }
  }

  return 'plain';
}

/**
 * 清洗单行输入，对齐原版 rule-parser.js 清洗逻辑
 * @param {string} line - 原始行
 * @returns {{ cleaned: string, isComment: boolean, noResolve: string }}
 */
function cleanLine(line) {
  let x = line;

  // 去掉 payload: 前缀
  x = x.replace(/^payload:/, '');

  // 将行首 //、#、; 注释统一转为 # 开头
  x = x.replace(/^ *(#|;|\/\/)/, '#');

  // 去掉行首 YAML 列表标记 "- "
  x = x.replace(/^ *- */, '');

  // 对非注释行，去掉行尾 " // ..." 注释
  x = x.replace(/(^[^#].+)\x20+\/\/.+/, '$1');

  // 提取 no-resolve（去空格后大小写不敏感匹配）
  const noResolve = x.replace(/\x20/g, '').match(/,no-resolve/i) ? ',no-resolve' : '';

  // 移除 no-resolve 以便后续解析
  x = x.replace(/,?\s*no-resolve/gi, '');

  // 保护正则量词中的逗号 {n,m}
  x = x.replace(/(\{[0-9]+)\,([0-9]*\})/g, '$1' + COMMA_PLACEHOLDER + '$2');

  // 移除脚本/元数据行（包含 [、=、{、\ 或 .js 的行，但排除以 U 开头的 URL 规则）
  x = x.replace(/(^[^U].*(\[|=|{|\\|\/.*\.js).*)/i, '');

  // 去掉引号
  x = x.replace(/'|"/g, '');

  // 将 .example.com / *example.com / +example.com 转为 DOMAIN-SUFFIX,example.com
  x = x.replace(/^(\.|\*|\+)\.?/, 'DOMAIN-SUFFIX,');

  // 移除 INI section 行和空行
  x = x.replace(/^\[.*|^\s*$/, '');

  return {
    cleaned: x,
    isComment: /^#/.test(x),
    noResolve
  };
}

/**
 * 恢复正则量词中的逗号
 * @param {string} line - 处理后的行
 * @returns {string} 原始行
 */
function restoreRegex(line) {
  return line.replace(new RegExp(COMMA_PLACEHOLDER, 'g'), ',');
}

/**
 * 检查规则类型是否受支持
 * @param {string} type - 规则类型
 * @returns {boolean}
 */
function isSupportedType(type) {
  return SUPPORTED_TYPES.includes(type);
}

/**
 * 智能推断规则类型
 * @param {string} value - 规则值
 * @returns {{ type: string, value: string, supported: boolean, noResolve: string }}
 */
function inferRuleType(value) {
  // IPv4 地址格式
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/.test(value)) {
    return { type: 'IP-CIDR', value, supported: true, noResolve: '' };
  }

  // IPv6 地址格式
  if (/^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))(\/\d{1,3})?$/.test(value)) {
    return { type: 'IP-CIDR6', value, supported: true, noResolve: '' };
  }

  // 域名格式（包含顶级域名）
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(value)) {
    return { type: 'DOMAIN', value, supported: true, noResolve: '' };
  }

  // 域名后缀格式（必须包含点号）
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/.test(value)) {
    return { type: 'DOMAIN-SUFFIX', value, supported: true, noResolve: '' };
  }

  // 关键词格式（仅字母、数字、连字符）
  if (/^[a-zA-Z0-9-]+$/.test(value)) {
    return { type: 'DOMAIN-KEYWORD', value, supported: true, noResolve: '' };
  }

  // 默认标记为不支持
  return { type: 'UNKNOWN', value, supported: false, noResolve: '' };
}

/**
 * 解析端口规则，支持多端口拆分
 * @param {string} type - 规则类型 (SRC-PORT / DST-PORT)
 * @param {string} value - 端口值（可能包含 / 或 , 分隔的多端口）
 * @param {string} noResolve - no-resolve 标志
 * @returns {Array} 拆分后的规则数组
 */
function parsePortRule(type, value, noResolve) {
  const ports = value.replace(/,/g, '/').split('/').filter(Boolean);

  return ports.map(port => ({
    type,
    value: port.trim(),
    supported: true,
    noResolve
  }));
}

/**
 * 提取逻辑规则中的子规则字符串
 * @param {string} content - 括号内容，如 "(DOMAIN,example.com),(DST-PORT,443)" 或 "((DOMAIN,example.com),(DST-PORT,443))"
 * @returns {string[]} 子规则字符串数组
 */
function extractSubRules(content) {
  // 处理 ((...)) 格式：剥离一层括号
  let str = content;
  if (str.startsWith('((') && str.endsWith('))')) {
    str = str.slice(1, -1);
  }

  const rules = [];
  let depth = 0;
  let current = '';

  for (const char of str) {
    if (char === '(') {
      if (depth > 0) current += char;
      depth++;
    } else if (char === ')') {
      depth--;
      if (depth === 0) {
        rules.push(current);
        current = '';
      } else {
        current += char;
      }
    } else if (depth > 0) {
      current += char;
    }
  }

  return rules;
}

/**
 * 解析逻辑规则（AND/OR/NOT）
 * @param {string} type - 逻辑类型
 * @param {string} operandsStr - 操作数括号内容
 * @param {string} policy - 策略名
 * @param {string} noResolve - no-resolve 标志
 * @returns {Object} 复合规则对象
 */
function parseLogicRule(type, operandsStr, policy, noResolve) {
  const subRuleStrings = extractSubRules(operandsStr);

  const operands = subRuleStrings.map(str => {
    // 剥离子规则外层 ()
    const inner = str.startsWith('(') && str.endsWith(')') ? str.slice(1, -1) : str;
    const commaIdx = inner.indexOf(',');
    if (commaIdx === -1) {
      return { type: inner.toUpperCase().trim(), value: '', supported: false, noResolve: '' };
    }
    const subType = inner.substring(0, commaIdx).toUpperCase().trim();
    const subValue = inner.substring(commaIdx + 1).trim();
    return {
      type: subType,
      value: subValue,
      supported: isSupportedType(subType),
      noResolve: ''
    };
  });

  const allSupported = operands.every(op => op.supported);

  return {
    type,
    operands,
    policy,
    supported: allSupported,
    noResolve
  };
}

/**
 * 解析单行规则
 * @param {string} line - 规则行
 * @returns {Array<{ type: string, value: string, supported: boolean, noResolve: string }>}
 */
function parseRuleLine(line) {
  // 清洗输入
  const { cleaned, isComment, noResolve } = cleanLine(line);

  // 跳过注释和空行
  if (isComment || !cleaned) {
    return [];
  }

  // 分割类型和值
  const parts = cleaned.split(',');

  if (parts.length >= 2) {
    const type = parts[0].toUpperCase().trim();

    // 逻辑规则特殊处理
    if ((type === 'AND' || type === 'OR' || type === 'NOT') && cleaned.includes('((')) {
      const startIdx = cleaned.indexOf('((');
      let depth = 0;
      let endIdx = -1;
      for (let i = startIdx; i < cleaned.length; i++) {
        if (cleaned[i] === '(') depth++;
        else if (cleaned[i] === ')') depth--;
        if (depth === 0) { endIdx = i; break; }
      }
      if (endIdx === -1) return [];
      const operandsStr = cleaned.substring(startIdx, endIdx + 1);
      const afterOperands = cleaned.substring(endIdx + 1);
      const policyMatch = afterOperands.match(/,([^,]+)$/);
      const policy = policyMatch ? policyMatch[1].trim() : 'DIRECT';
      return [parseLogicRule(type, operandsStr, policy, noResolve)];
    }

    // 端口规则特殊处理：收集所有端口值
    if (type === 'SRC-PORT' || type === 'DST-PORT') {
      const portParts = [];
      for (let i = 1; i < parts.length; i++) {
        const part = parts[i].trim();
        // 包含斜杠的组合（如 114-514/810-1919），按斜杠拆分
        if (part.includes('/')) {
          portParts.push(...part.split('/').filter(Boolean));
        }
        // 纯数字或范围（如 8000-9000）
        else if (/^\d+(-\d+)?$/.test(part)) {
          portParts.push(part);
        }
        // 非端口值（如策略名 REJECT、no-resolve），停止收集
        else {
          break;
        }
      }
      if (portParts.length > 0) {
        const value = restoreRegex(portParts.join(','));
        return parsePortRule(type, value, noResolve);
      }
      return [];
    }

    // 非端口规则：只取 parts[1]
    const value = restoreRegex(parts[1].trim());

    if (!value) {
      return [];
    }

    return [{
      type,
      value,
      supported: isSupportedType(type),
      noResolve
    }];
  }

  // 无逗号行，智能推断类型
  const value = restoreRegex(cleaned.trim());
  if (!value) {
    return [];
  }

  const inferred = inferRuleType(value);
  inferred.noResolve = noResolve;
  return [inferred];
}

/**
 * 解析纯文本格式规则集
 * @param {string} text - 规则集文本
 * @returns {Array<{ type: string, value: string, supported: boolean, noResolve: string }>}
 */
function parsePlainText(text) {
  const lines = text.split('\n');
  const rules = [];

  for (const line of lines) {
    const lineRules = parseRuleLine(line);
    rules.push(...lineRules);
  }

  return rules;
}

/**
 * 解析 Clash 规则集
 * @param {string} text - 规则集文本
 * @returns {Array<{ type: string, value: string, supported: boolean, noResolve: string }>}
 */
function parseClashRules(text) {
  if (!text || typeof text !== 'string') {
    return [];
  }

  return parsePlainText(text);
}

/**
 * Loon 规则生成器
 * 将解析后的规则对象转换为 Loon 格式规则集
 * 对齐原版 rule-parser.js 的 Loon 分支逻辑
 */

// 类型映射表
const TYPE_MAPPING = {
  'DOMAIN': 'DOMAIN',
  'DOMAIN-SUFFIX': 'DOMAIN-SUFFIX',
  'DOMAIN-KEYWORD': 'DOMAIN-KEYWORD',
  'IP-CIDR': 'IP-CIDR',
  'IP-CIDR6': 'IP-CIDR6',
  'SRC-IP-CIDR': 'SRC-IP-CIDR',
  'GEOIP': 'GEOIP',
  'SRC-PORT': 'SRC-PORT',
  'DST-PORT': 'DEST-PORT',
  'NETWORK': 'PROTOCOL',
  'MATCH': 'FINAL'
};

/**
 * 过滤不支持的规则
 * @param {Array<{ type: string, supported: boolean }>} rules - 规则数组
 * @returns {Array} 过滤后的规则
 */
function filterUnsupported(rules) {
  return rules.filter(rule => rule.supported);
}

/**
 * 格式化单条 Loon 规则
 * @param {{ type: string, value: string, noResolve: string, operands?: Array, policy?: string }} rule - 规则对象
 * @returns {string|null} 格式化后的规则字符串
 */
function formatLoonRule(rule) {
  // 逻辑规则
  if (rule.type === 'AND' || rule.type === 'OR' || rule.type === 'NOT') {
    const subRules = rule.operands.map(operand => {
      const mappedType = TYPE_MAPPING[operand.type] || operand.type;
      return `(${mappedType},${operand.value}${operand.noResolve || ''})`;
    }).join(',');
    return `${rule.type},(${subRules}),${rule.policy}`;
  }

  const mappedType = TYPE_MAPPING[rule.type];

  if (!mappedType) {
    return null;
  }

  // 处理 MATCH 类型
  if (rule.type === 'MATCH') {
    return 'FINAL';
  }

  // 普通规则
  return `${mappedType},${rule.value}${rule.noResolve}`;
}

/**
 * 生成统计信息头
 * @param {number} originalCount - 原始规则数量
 * @param {Array} convertedRules - 转换后的规则数组
 * @param {Array} unsupportedRules - 不支持的规则数组
 * @returns {string} 统计信息头
 */
function generateStatsHeader(originalCount, convertedRules, unsupportedRules) {
  const lines = [
    '# Loon 规则集',
    `# 生成时间: ${new Date().toISOString()}`,
    `# 原始规则数: ${originalCount}`,
    `# 转换规则数: ${convertedRules.length}`,
    `# 不支持规则数: ${unsupportedRules.length}`,
    ''
  ];

  return lines.join('\n');
}

/**
 * 生成 Loon 规则集
 * @param {Array<{ type: string, value: string, supported: boolean, noResolve: string }>} rules - 规则数组
 * @param {number} [originalCount] - 原始规则数量（拆分前），默认使用 rules.length
 * @returns {string} Loon 规则集文本
 */
function generateLoonRules(rules, originalCount) {
  const supportedRules = filterUnsupported(rules);
  const unsupportedRules = rules.filter(r => !r.supported);

  const loonRules = [];

  for (const rule of supportedRules) {
    const formatted = formatLoonRule(rule);
    if (formatted) {
      loonRules.push(formatted);
    }
  }

  const header = generateStatsHeader(originalCount !== undefined ? originalCount : rules.length, loonRules, unsupportedRules);

  return header + loonRules.join('\n');
}

/**
 * 转换主逻辑
 * 将 Clash 规则集转换为 Loon 规则集
 */

// 错误代码
const ERROR_CODES = {
  INVALID_INPUT: 'INVALID_INPUT',
  PARSE_ERROR: 'PARSE_ERROR',
  NO_RULES: 'NO_RULES',
  GENERATION_ERROR: 'GENERATION_ERROR'
};

/**
 * 自定义转换错误类
 */
class ConverterError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'ConverterError';
    this.code = code;
    this.details = details;
  }
}

/**
 * 验证输入文本
 * @param {string} text - 输入文本
 * @throws {ConverterError}
 */
function validateInput(text) {
  if (!text || typeof text !== 'string') {
    throw new ConverterError('无效的输入文本', ERROR_CODES.INVALID_INPUT);
  }

  if (text.length > 10 * 1024 * 1024) {
    throw new ConverterError('输入文件过大（超过 10MB）', ERROR_CODES.INVALID_INPUT);
  }
}

/**
 * 将 Clash 规则集转换为 Loon 规则集
 * @param {string} text - Clash 规则集文本
 * @returns {string} Loon 规则集文本
 * @throws {ConverterError}
 */
function convertClashToLoon(text) {
  try {
    validateInput(text);

    // 兼容浏览器和 Node 两种环境
    const _parseClashRules = parseClashRules;
    const _generateLoonRules = generateLoonRules;

    // 计算原始规则数（拆分前的非空非注释行数）
    const originalCount = text.split('\n').filter(line => {
      const trimmed = line.trim();
      return trimmed && !trimmed.startsWith('#') && !trimmed.startsWith('//') && !trimmed.startsWith(';');
    }).length;

    const rules = _parseClashRules(text);

    if (rules.length === 0) {
      throw new ConverterError('未找到有效的规则', ERROR_CODES.NO_RULES);
    }

    return _generateLoonRules(rules, originalCount);

  } catch (error) {
    if (error instanceof ConverterError) {
      throw error;
    }

    throw new ConverterError(
      `转换失败: ${error.message}`,
      ERROR_CODES.PARSE_ERROR,
      { originalError: error.message }
    );
  }
}

/**
 * 从 URL 获取规则集内容
 * @param {string} url - 规则集 URL
 * @returns {Promise<string>} 规则集文本
 * @throws {ConverterError}
 */
async function fetchRulesFromUrl(url) {
  try {
    if (!url || typeof url !== 'string') {
      throw new ConverterError('无效的 URL', ERROR_CODES.INVALID_INPUT);
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch {
      throw new ConverterError('无效的 URL 格式', ERROR_CODES.INVALID_INPUT);
    }

    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      throw new ConverterError('只支持 HTTP/HTTPS 协议', ERROR_CODES.INVALID_INPUT);
    }

    const response = await fetch(url, {
      headers: { 'User-Agent': RULE_HUB_UA }
    });

    if (!response.ok) {
      throw new ConverterError(
        `HTTP ${response.status}: ${response.statusText}`,
        ERROR_CODES.PARSE_ERROR
      );
    }

    return await response.text();

  } catch (error) {
    if (error instanceof ConverterError) {
      throw error;
    }

    throw new ConverterError(
      `获取 URL 失败: ${error.message}`,
      ERROR_CODES.PARSE_ERROR,
      { url }
    );
  }
}

/**
 * 解析统计信息
 * @param {string} loonText - Loon 规则集文本
 * @returns {{ originalCount: number, convertedCount: number, unsupportedCount: number, timestamp: string }}
 */
function parseStats(loonText) {
  const lines = loonText.split('\n');
  const stats = {
    originalCount: 0,
    convertedCount: 0,
    unsupportedCount: 0,
    timestamp: ''
  };

  for (const line of lines) {
    if (line.startsWith('# 原始规则数:')) {
      stats.originalCount = parseInt(line.split(':')[1].trim(), 10);
    } else if (line.startsWith('# 转换规则数:')) {
      stats.convertedCount = parseInt(line.split(':')[1].trim(), 10);
    } else if (line.startsWith('# 不支持规则数:')) {
      stats.unsupportedCount = parseInt(line.split(':')[1].trim(), 10);
    } else if (line.startsWith('# 生成时间:')) {
      stats.timestamp = line.split(':').slice(1).join(':').trim();
    }
  }

  return stats;
}


var url = $request.url;

if (url.match(/\/convert(\?|$)/)) {
  // === 转换接口 ===
  var sourceUrl = (url.match(/[?&]url=([^&]+)/) || [])[1] || '';
  if (!sourceUrl) {
    $done({ response: { status: 400, body: 'Missing url parameter', headers: { 'Content-Type': 'text/plain' } } });
  } else {
    sourceUrl = decodeURIComponent(sourceUrl);
    $httpClient.get({ url: sourceUrl, headers: { 'User-Agent': 'rule-hub/1.3.0' } }, function(err, resp, data) {
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
      body: "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n  <meta charset=\"UTF-8\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n  <title>Rule-Hub</title>\n  <style>\n    *{margin:0;padding:0;box-sizing:border-box}\n    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,Cantarell,'Open Sans','Helvetica Neue',sans-serif;line-height:1.6;color:#333;background:#f5f5f5;min-height:100vh}\n    .container{max-width:900px;margin:0 auto;padding:20px}\n    header{text-align:center;margin-bottom:30px}\n    header h1{font-size:24px;color:#2c3e50;margin-bottom:8px}\n    header p{color:#666;font-size:14px}\n    .card{background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);padding:20px;margin-bottom:20px}\n    .card-title{font-size:16px;font-weight:600;color:#2c3e50;margin-bottom:15px;padding-bottom:10px;border-bottom:1px solid #eee}\n    .mode-switch{display:flex;gap:10px;margin-bottom:15px}\n    .mode-btn{flex:1;padding:10px 16px;border:2px solid #e0e0e0;border-radius:6px;background:#fff;color:#666;font-size:14px;cursor:pointer;transition:all .2s}\n    .mode-btn:hover{border-color:#3498db;color:#3498db}\n    .mode-btn.active{border-color:#3498db;background:#3498db;color:#fff}\n    .input-area{margin-bottom:15px}\n    .input-area label{display:block;font-size:14px;color:#555;margin-bottom:8px}\n    .input-area input[type=\"text\"],.input-area textarea{width:100%;padding:12px;border:1px solid #ddd;border-radius:6px;font-size:14px;font-family:'Monaco','Menlo','Ubuntu Mono',monospace;transition:border-color .2s}\n    .input-area input[type=\"text\"]:focus,.input-area textarea:focus{outline:none;border-color:#3498db;box-shadow:0 0 0 3px rgba(52,152,219,.1)}\n    .input-area textarea{min-height:200px;resize:vertical}\n    .actions{display:flex;gap:10px;margin-bottom:15px}\n    .btn{padding:10px 20px;border:none;border-radius:6px;font-size:14px;font-weight:500;cursor:pointer;transition:all .2s}\n    .btn:disabled{opacity:.5;cursor:not-allowed}\n    .btn-primary{background:#3498db;color:#fff}\n    .btn-primary:hover:not(:disabled){background:#2980b9}\n    .btn-secondary{background:#95a5a6;color:#fff}\n    .btn-secondary:hover:not(:disabled){background:#7f8c8d}\n    .btn-success{background:#27ae60;color:#fff}\n    .btn-success:hover:not(:disabled){background:#229954}\n    .loading{display:flex;align-items:center;justify-content:center;gap:10px;padding:20px;color:#666}\n    .spinner{width:20px;height:20px;border:2px solid #e0e0e0;border-top-color:#3498db;border-radius:50%;animation:spin .8s linear infinite}\n    @keyframes spin{to{transform:rotate(360deg)}}\n    .error{background:#fee;border:1px solid #fcc;border-radius:6px;padding:12px;margin-bottom:15px;color:#c00;font-size:14px;display:flex;justify-content:space-between;align-items:center}\n    .error-close{background:none;border:none;color:#c00;cursor:pointer;font-size:18px;padding:0 5px}\n    .stats{display:flex;gap:20px;flex-wrap:wrap;margin-bottom:15px;padding:12px;background:#f8f9fa;border-radius:6px}\n    .stat-item{font-size:13px;color:#666}\n    .stat-item span{font-weight:600;color:#333}\n    .output-area textarea{width:100%;min-height:200px;padding:12px;border:1px solid #ddd;border-radius:6px;font-size:14px;font-family:'Monaco','Menlo','Ubuntu Mono',monospace;background:#f8f9fa;resize:vertical}\n    .output-actions{display:flex;gap:10px;margin-top:10px}\n    .toast{position:fixed;top:20px;right:20px;background:#333;color:#fff;padding:12px 20px;border-radius:6px;font-size:14px;z-index:1000;animation:fadeInOut 2s ease-in-out}\n    @keyframes fadeInOut{0%{opacity:0;transform:translateY(-10px)}15%{opacity:1;transform:translateY(0)}85%{opacity:1;transform:translateY(0)}100%{opacity:0;transform:translateY(-10px)}}\n    @media(max-width:600px){.container{padding:10px}.mode-switch{flex-direction:column}.actions{flex-direction:column}.btn{width:100%}.stats{flex-direction:column;gap:8px}}\n  </style>\n</head>\n<body>\n  <div id=\"app\">\n    <div class=\"container\">\n      <header>\n        <h1>Rule-Hub</h1>\n        <p>将 Clash 规则集转换为 Loon 规则集</p>\n      </header>\n      <div class=\"card\">\n        <div class=\"card-title\">输入规则</div>\n        <div class=\"mode-switch\">\n          <button class=\"mode-btn active\" data-mode=\"url\" onclick=\"switchMode('url')\">URL 获取</button>\n          <button class=\"mode-btn\" data-mode=\"text\" onclick=\"switchMode('text')\">粘贴文本</button>\n        </div>\n        <div id=\"url-input\" class=\"input-area\">\n          <label>规则集 URL</label>\n          <input type=\"text\" id=\"inputUrl\" placeholder=\"https://example.com/rules.yaml\">\n        </div>\n        <div id=\"text-input\" class=\"input-area\" style=\"display:none\">\n          <label>Clash 规则集</label>\n          <textarea id=\"inputText\" placeholder=\"粘贴 Clash 规则集内容...\"></textarea>\n        </div>\n        <div class=\"actions\">\n          <button class=\"btn btn-primary\" id=\"convertBtn\" onclick=\"doConvert()\">开始转换</button>\n          <button class=\"btn btn-secondary\" onclick=\"doClear()\">清空</button>\n        </div>\n      </div>\n      <div id=\"error-box\" class=\"error\" style=\"display:none\">\n        <span id=\"error-msg\"></span>\n        <button class=\"error-close\" onclick=\"hideError()\">&times;</button>\n      </div>\n      <div id=\"loading\" class=\"loading\" style=\"display:none\">\n        <div class=\"spinner\"></div>\n        <span>正在转换...</span>\n      </div>\n      <div id=\"output-card\" class=\"card\" style=\"display:none\">\n        <div class=\"card-title\">转换结果</div>\n        <div id=\"stats\" class=\"stats\" style=\"display:none\">\n          <div class=\"stat-item\">原始规则: <span id=\"stat-original\">0</span></div>\n          <div class=\"stat-item\">转换成功: <span id=\"stat-converted\">0</span></div>\n          <div class=\"stat-item\">不支持: <span id=\"stat-unsupported\">0</span></div>\n        </div>\n        <div class=\"output-area\">\n          <textarea id=\"outputText\" readonly></textarea>\n        </div>\n        <div class=\"output-actions\">\n          <button class=\"btn btn-primary\" id=\"copyLinkBtn\" onclick=\"doCopyLink()\" style=\"display:none\">复制链接</button>\n          <button class=\"btn btn-success\" onclick=\"doCopy()\">复制结果</button>\n        </div>\n      </div>\n    </div>\n    <div id=\"toast\" class=\"toast\" style=\"display:none\"></div>\n  </div>\n  <script>\n  var RULE_HUB_UA = 'rule-hub/1.3.0';\n  /**\r\n * Clash 规则解析器\r\n * 支持 YAML 格式和纯文本格式的 Clash 规则集解析\r\n * 输入清洗逻辑对齐原版 rule-parser.js\r\n */\r\n\r\n// 支持的规则类型\r\nconst SUPPORTED_TYPES = [\r\n  'DOMAIN',\r\n  'DOMAIN-SUFFIX',\r\n  'DOMAIN-KEYWORD',\r\n  'IP-CIDR',\r\n  'IP-CIDR6',\r\n  'SRC-IP-CIDR',\r\n  'GEOIP',\r\n  'SRC-PORT',\r\n  'DST-PORT',\r\n  'NETWORK',\r\n  'MATCH',\r\n  'AND',\r\n  'OR',\r\n  'NOT'\r\n];\r\n\r\n// 正则量词逗号保护占位符（与原版 t&zd; 一致）\r\nconst COMMA_PLACEHOLDER = 't&zd;';\r\n\r\n/**\r\n * 检测规则集格式\r\n * @param {string} text - 规则集文本\r\n * @returns {'yaml'|'plain'} 格式类型\r\n */\r\nfunction detectFormat(text) {\r\n  const lines = text.split('\\n');\r\n\r\n  for (const line of lines) {\r\n    const trimmed = line.trim();\r\n\r\n    if (trimmed.startsWith('payload:')) {\r\n      return 'yaml';\r\n    }\r\n\r\n    if (trimmed.startsWith('- ')) {\r\n      return 'yaml';\r\n    }\r\n  }\r\n\r\n  return 'plain';\r\n}\r\n\r\n/**\r\n * 清洗单行输入，对齐原版 rule-parser.js 清洗逻辑\r\n * @param {string} line - 原始行\r\n * @returns {{ cleaned: string, isComment: boolean, noResolve: string }}\r\n */\r\nfunction cleanLine(line) {\r\n  let x = line;\r\n\r\n  // 去掉 payload: 前缀\r\n  x = x.replace(/^payload:/, '');\r\n\r\n  // 将行首 //、#、; 注释统一转为 # 开头\r\n  x = x.replace(/^ *(#|;|\\/\\/)/, '#');\r\n\r\n  // 去掉行首 YAML 列表标记 \"- \"\r\n  x = x.replace(/^ *- */, '');\r\n\r\n  // 对非注释行，去掉行尾 \" // ...\" 注释\r\n  x = x.replace(/(^[^#].+)\\x20+\\/\\/.+/, '$1');\r\n\r\n  // 提取 no-resolve（去空格后大小写不敏感匹配）\r\n  const noResolve = x.replace(/\\x20/g, '').match(/,no-resolve/i) ? ',no-resolve' : '';\r\n\r\n  // 移除 no-resolve 以便后续解析\r\n  x = x.replace(/,?\\s*no-resolve/gi, '');\r\n\r\n  // 保护正则量词中的逗号 {n,m}\r\n  x = x.replace(/(\\{[0-9]+)\\,([0-9]*\\})/g, '$1' + COMMA_PLACEHOLDER + '$2');\r\n\r\n  // 移除脚本/元数据行（包含 [、=、{、\\ 或 .js 的行，但排除以 U 开头的 URL 规则）\r\n  x = x.replace(/(^[^U].*(\\[|=|{|\\\\|\\/.*\\.js).*)/i, '');\r\n\r\n  // 去掉引号\r\n  x = x.replace(/'|\"/g, '');\r\n\r\n  // 将 .example.com / *example.com / +example.com 转为 DOMAIN-SUFFIX,example.com\r\n  x = x.replace(/^(\\.|\\*|\\+)\\.?/, 'DOMAIN-SUFFIX,');\r\n\r\n  // 移除 INI section 行和空行\r\n  x = x.replace(/^\\[.*|^\\s*$/, '');\r\n\r\n  return {\r\n    cleaned: x,\r\n    isComment: /^#/.test(x),\r\n    noResolve\r\n  };\r\n}\r\n\r\n/**\r\n * 恢复正则量词中的逗号\r\n * @param {string} line - 处理后的行\r\n * @returns {string} 原始行\r\n */\r\nfunction restoreRegex(line) {\r\n  return line.replace(new RegExp(COMMA_PLACEHOLDER, 'g'), ',');\r\n}\r\n\r\n/**\r\n * 检查规则类型是否受支持\r\n * @param {string} type - 规则类型\r\n * @returns {boolean}\r\n */\r\nfunction isSupportedType(type) {\r\n  return SUPPORTED_TYPES.includes(type);\r\n}\r\n\r\n/**\r\n * 智能推断规则类型\r\n * @param {string} value - 规则值\r\n * @returns {{ type: string, value: string, supported: boolean, noResolve: string }}\r\n */\r\nfunction inferRuleType(value) {\r\n  // IPv4 地址格式\r\n  if (/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(\\/\\d{1,2})?$/.test(value)) {\r\n    return { type: 'IP-CIDR', value, supported: true, noResolve: '' };\r\n  }\r\n\r\n  // IPv6 地址格式\r\n  if (/^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))(\\/\\d{1,3})?$/.test(value)) {\r\n    return { type: 'IP-CIDR6', value, supported: true, noResolve: '' };\r\n  }\r\n\r\n  // 域名格式（包含顶级域名）\r\n  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\\.[a-zA-Z]{2,}$/.test(value)) {\r\n    return { type: 'DOMAIN', value, supported: true, noResolve: '' };\r\n  }\r\n\r\n  // 域名后缀格式（必须包含点号）\r\n  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/.test(value)) {\r\n    return { type: 'DOMAIN-SUFFIX', value, supported: true, noResolve: '' };\r\n  }\r\n\r\n  // 关键词格式（仅字母、数字、连字符）\r\n  if (/^[a-zA-Z0-9-]+$/.test(value)) {\r\n    return { type: 'DOMAIN-KEYWORD', value, supported: true, noResolve: '' };\r\n  }\r\n\r\n  // 默认标记为不支持\r\n  return { type: 'UNKNOWN', value, supported: false, noResolve: '' };\r\n}\r\n\r\n/**\r\n * 解析端口规则，支持多端口拆分\r\n * @param {string} type - 规则类型 (SRC-PORT / DST-PORT)\r\n * @param {string} value - 端口值（可能包含 / 或 , 分隔的多端口）\r\n * @param {string} noResolve - no-resolve 标志\r\n * @returns {Array} 拆分后的规则数组\r\n */\r\nfunction parsePortRule(type, value, noResolve) {\r\n  const ports = value.replace(/,/g, '/').split('/').filter(Boolean);\r\n\r\n  return ports.map(port => ({\r\n    type,\r\n    value: port.trim(),\r\n    supported: true,\r\n    noResolve\r\n  }));\r\n}\r\n\r\n/**\r\n * 提取逻辑规则中的子规则字符串\r\n * @param {string} content - 括号内容，如 \"(DOMAIN,example.com),(DST-PORT,443)\" 或 \"((DOMAIN,example.com),(DST-PORT,443))\"\r\n * @returns {string[]} 子规则字符串数组\r\n */\r\nfunction extractSubRules(content) {\r\n  // 处理 ((...)) 格式：剥离一层括号\r\n  let str = content;\r\n  if (str.startsWith('((') && str.endsWith('))')) {\r\n    str = str.slice(1, -1);\r\n  }\r\n\r\n  const rules = [];\r\n  let depth = 0;\r\n  let current = '';\r\n\r\n  for (const char of str) {\r\n    if (char === '(') {\r\n      if (depth > 0) current += char;\r\n      depth++;\r\n    } else if (char === ')') {\r\n      depth--;\r\n      if (depth === 0) {\r\n        rules.push(current);\r\n        current = '';\r\n      } else {\r\n        current += char;\r\n      }\r\n    } else if (depth > 0) {\r\n      current += char;\r\n    }\r\n  }\r\n\r\n  return rules;\r\n}\r\n\r\n/**\r\n * 解析逻辑规则（AND/OR/NOT）\r\n * @param {string} type - 逻辑类型\r\n * @param {string} operandsStr - 操作数括号内容\r\n * @param {string} policy - 策略名\r\n * @param {string} noResolve - no-resolve 标志\r\n * @returns {Object} 复合规则对象\r\n */\r\nfunction parseLogicRule(type, operandsStr, policy, noResolve) {\r\n  const subRuleStrings = extractSubRules(operandsStr);\r\n\r\n  const operands = subRuleStrings.map(str => {\r\n    // 剥离子规则外层 ()\r\n    const inner = str.startsWith('(') && str.endsWith(')') ? str.slice(1, -1) : str;\r\n    const commaIdx = inner.indexOf(',');\r\n    if (commaIdx === -1) {\r\n      return { type: inner.toUpperCase().trim(), value: '', supported: false, noResolve: '' };\r\n    }\r\n    const subType = inner.substring(0, commaIdx).toUpperCase().trim();\r\n    const subValue = inner.substring(commaIdx + 1).trim();\r\n    return {\r\n      type: subType,\r\n      value: subValue,\r\n      supported: isSupportedType(subType),\r\n      noResolve: ''\r\n    };\r\n  });\r\n\r\n  const allSupported = operands.every(op => op.supported);\r\n\r\n  return {\r\n    type,\r\n    operands,\r\n    policy,\r\n    supported: allSupported,\r\n    noResolve\r\n  };\r\n}\r\n\r\n/**\r\n * 解析单行规则\r\n * @param {string} line - 规则行\r\n * @returns {Array<{ type: string, value: string, supported: boolean, noResolve: string }>}\r\n */\r\nfunction parseRuleLine(line) {\r\n  // 清洗输入\r\n  const { cleaned, isComment, noResolve } = cleanLine(line);\r\n\r\n  // 跳过注释和空行\r\n  if (isComment || !cleaned) {\r\n    return [];\r\n  }\r\n\r\n  // 分割类型和值\r\n  const parts = cleaned.split(',');\r\n\r\n  if (parts.length >= 2) {\r\n    const type = parts[0].toUpperCase().trim();\r\n\r\n    // 逻辑规则特殊处理\r\n    if ((type === 'AND' || type === 'OR' || type === 'NOT') && cleaned.includes('((')) {\r\n      const startIdx = cleaned.indexOf('((');\r\n      let depth = 0;\r\n      let endIdx = -1;\r\n      for (let i = startIdx; i < cleaned.length; i++) {\r\n        if (cleaned[i] === '(') depth++;\r\n        else if (cleaned[i] === ')') depth--;\r\n        if (depth === 0) { endIdx = i; break; }\r\n      }\r\n      if (endIdx === -1) return [];\r\n      const operandsStr = cleaned.substring(startIdx, endIdx + 1);\r\n      const afterOperands = cleaned.substring(endIdx + 1);\r\n      const policyMatch = afterOperands.match(/,([^,]+)$/);\r\n      const policy = policyMatch ? policyMatch[1].trim() : 'DIRECT';\r\n      return [parseLogicRule(type, operandsStr, policy, noResolve)];\r\n    }\r\n\r\n    // 端口规则特殊处理：收集所有端口值\r\n    if (type === 'SRC-PORT' || type === 'DST-PORT') {\r\n      const portParts = [];\r\n      for (let i = 1; i < parts.length; i++) {\r\n        const part = parts[i].trim();\r\n        // 包含斜杠的组合（如 114-514/810-1919），按斜杠拆分\r\n        if (part.includes('/')) {\r\n          portParts.push(...part.split('/').filter(Boolean));\r\n        }\r\n        // 纯数字或范围（如 8000-9000）\r\n        else if (/^\\d+(-\\d+)?$/.test(part)) {\r\n          portParts.push(part);\r\n        }\r\n        // 非端口值（如策略名 REJECT、no-resolve），停止收集\r\n        else {\r\n          break;\r\n        }\r\n      }\r\n      if (portParts.length > 0) {\r\n        const value = restoreRegex(portParts.join(','));\r\n        return parsePortRule(type, value, noResolve);\r\n      }\r\n      return [];\r\n    }\r\n\r\n    // 非端口规则：只取 parts[1]\r\n    const value = restoreRegex(parts[1].trim());\r\n\r\n    if (!value) {\r\n      return [];\r\n    }\r\n\r\n    return [{\r\n      type,\r\n      value,\r\n      supported: isSupportedType(type),\r\n      noResolve\r\n    }];\r\n  }\r\n\r\n  // 无逗号行，智能推断类型\r\n  const value = restoreRegex(cleaned.trim());\r\n  if (!value) {\r\n    return [];\r\n  }\r\n\r\n  const inferred = inferRuleType(value);\r\n  inferred.noResolve = noResolve;\r\n  return [inferred];\r\n}\r\n\r\n/**\r\n * 解析纯文本格式规则集\r\n * @param {string} text - 规则集文本\r\n * @returns {Array<{ type: string, value: string, supported: boolean, noResolve: string }>}\r\n */\r\nfunction parsePlainText(text) {\r\n  const lines = text.split('\\n');\r\n  const rules = [];\r\n\r\n  for (const line of lines) {\r\n    const lineRules = parseRuleLine(line);\r\n    rules.push(...lineRules);\r\n  }\r\n\r\n  return rules;\r\n}\r\n\r\n/**\r\n * 解析 Clash 规则集\r\n * @param {string} text - 规则集文本\r\n * @returns {Array<{ type: string, value: string, supported: boolean, noResolve: string }>}\r\n */\r\nfunction parseClashRules(text) {\r\n  if (!text || typeof text !== 'string') {\r\n    return [];\r\n  }\r\n\r\n  return parsePlainText(text);\r\n}\n\n/**\r\n * Loon 规则生成器\r\n * 将解析后的规则对象转换为 Loon 格式规则集\r\n * 对齐原版 rule-parser.js 的 Loon 分支逻辑\r\n */\r\n\r\n// 类型映射表\r\nconst TYPE_MAPPING = {\r\n  'DOMAIN': 'DOMAIN',\r\n  'DOMAIN-SUFFIX': 'DOMAIN-SUFFIX',\r\n  'DOMAIN-KEYWORD': 'DOMAIN-KEYWORD',\r\n  'IP-CIDR': 'IP-CIDR',\r\n  'IP-CIDR6': 'IP-CIDR6',\r\n  'SRC-IP-CIDR': 'SRC-IP-CIDR',\r\n  'GEOIP': 'GEOIP',\r\n  'SRC-PORT': 'SRC-PORT',\r\n  'DST-PORT': 'DEST-PORT',\r\n  'NETWORK': 'PROTOCOL',\r\n  'MATCH': 'FINAL'\r\n};\r\n\r\n/**\r\n * 过滤不支持的规则\r\n * @param {Array<{ type: string, supported: boolean }>} rules - 规则数组\r\n * @returns {Array} 过滤后的规则\r\n */\r\nfunction filterUnsupported(rules) {\r\n  return rules.filter(rule => rule.supported);\r\n}\r\n\r\n/**\r\n * 格式化单条 Loon 规则\r\n * @param {{ type: string, value: string, noResolve: string, operands?: Array, policy?: string }} rule - 规则对象\r\n * @returns {string|null} 格式化后的规则字符串\r\n */\r\nfunction formatLoonRule(rule) {\r\n  // 逻辑规则\r\n  if (rule.type === 'AND' || rule.type === 'OR' || rule.type === 'NOT') {\r\n    const subRules = rule.operands.map(operand => {\r\n      const mappedType = TYPE_MAPPING[operand.type] || operand.type;\r\n      return `(${mappedType},${operand.value}${operand.noResolve || ''})`;\r\n    }).join(',');\r\n    return `${rule.type},(${subRules}),${rule.policy}`;\r\n  }\r\n\r\n  const mappedType = TYPE_MAPPING[rule.type];\r\n\r\n  if (!mappedType) {\r\n    return null;\r\n  }\r\n\r\n  // 处理 MATCH 类型\r\n  if (rule.type === 'MATCH') {\r\n    return 'FINAL';\r\n  }\r\n\r\n  // 普通规则\r\n  return `${mappedType},${rule.value}${rule.noResolve}`;\r\n}\r\n\r\n/**\r\n * 生成统计信息头\r\n * @param {number} originalCount - 原始规则数量\r\n * @param {Array} convertedRules - 转换后的规则数组\r\n * @param {Array} unsupportedRules - 不支持的规则数组\r\n * @returns {string} 统计信息头\r\n */\r\nfunction generateStatsHeader(originalCount, convertedRules, unsupportedRules) {\r\n  const lines = [\r\n    '# Loon 规则集',\r\n    `# 生成时间: ${new Date().toISOString()}`,\r\n    `# 原始规则数: ${originalCount}`,\r\n    `# 转换规则数: ${convertedRules.length}`,\r\n    `# 不支持规则数: ${unsupportedRules.length}`,\r\n    ''\r\n  ];\r\n\r\n  return lines.join('\\n');\r\n}\r\n\r\n/**\r\n * 生成 Loon 规则集\r\n * @param {Array<{ type: string, value: string, supported: boolean, noResolve: string }>} rules - 规则数组\r\n * @param {number} [originalCount] - 原始规则数量（拆分前），默认使用 rules.length\r\n * @returns {string} Loon 规则集文本\r\n */\r\nfunction generateLoonRules(rules, originalCount) {\r\n  const supportedRules = filterUnsupported(rules);\r\n  const unsupportedRules = rules.filter(r => !r.supported);\r\n\r\n  const loonRules = [];\r\n\r\n  for (const rule of supportedRules) {\r\n    const formatted = formatLoonRule(rule);\r\n    if (formatted) {\r\n      loonRules.push(formatted);\r\n    }\r\n  }\r\n\r\n  const header = generateStatsHeader(originalCount !== undefined ? originalCount : rules.length, loonRules, unsupportedRules);\r\n\r\n  return header + loonRules.join('\\n');\r\n}\n\n/**\r\n * 转换主逻辑\r\n * 将 Clash 规则集转换为 Loon 规则集\r\n */\r\n\r\n// 错误代码\r\nconst ERROR_CODES = {\r\n  INVALID_INPUT: 'INVALID_INPUT',\r\n  PARSE_ERROR: 'PARSE_ERROR',\r\n  NO_RULES: 'NO_RULES',\r\n  GENERATION_ERROR: 'GENERATION_ERROR'\r\n};\r\n\r\n/**\r\n * 自定义转换错误类\r\n */\r\nclass ConverterError extends Error {\r\n  constructor(message, code, details = {}) {\r\n    super(message);\r\n    this.name = 'ConverterError';\r\n    this.code = code;\r\n    this.details = details;\r\n  }\r\n}\r\n\r\n/**\r\n * 验证输入文本\r\n * @param {string} text - 输入文本\r\n * @throws {ConverterError}\r\n */\r\nfunction validateInput(text) {\r\n  if (!text || typeof text !== 'string') {\r\n    throw new ConverterError('无效的输入文本', ERROR_CODES.INVALID_INPUT);\r\n  }\r\n\r\n  if (text.length > 10 * 1024 * 1024) {\r\n    throw new ConverterError('输入文件过大（超过 10MB）', ERROR_CODES.INVALID_INPUT);\r\n  }\r\n}\r\n\r\n/**\r\n * 将 Clash 规则集转换为 Loon 规则集\r\n * @param {string} text - Clash 规则集文本\r\n * @returns {string} Loon 规则集文本\r\n * @throws {ConverterError}\r\n */\r\nfunction convertClashToLoon(text) {\r\n  try {\r\n    validateInput(text);\r\n\r\n    // 兼容浏览器和 Node 两种环境\r\n    const _parseClashRules = parseClashRules;\r\n    const _generateLoonRules = generateLoonRules;\r\n\r\n    // 计算原始规则数（拆分前的非空非注释行数）\r\n    const originalCount = text.split('\\n').filter(line => {\r\n      const trimmed = line.trim();\r\n      return trimmed && !trimmed.startsWith('#') && !trimmed.startsWith('//') && !trimmed.startsWith(';');\r\n    }).length;\r\n\r\n    const rules = _parseClashRules(text);\r\n\r\n    if (rules.length === 0) {\r\n      throw new ConverterError('未找到有效的规则', ERROR_CODES.NO_RULES);\r\n    }\r\n\r\n    return _generateLoonRules(rules, originalCount);\r\n\r\n  } catch (error) {\r\n    if (error instanceof ConverterError) {\r\n      throw error;\r\n    }\r\n\r\n    throw new ConverterError(\r\n      `转换失败: ${error.message}`,\r\n      ERROR_CODES.PARSE_ERROR,\r\n      { originalError: error.message }\r\n    );\r\n  }\r\n}\r\n\r\n/**\r\n * 从 URL 获取规则集内容\r\n * @param {string} url - 规则集 URL\r\n * @returns {Promise<string>} 规则集文本\r\n * @throws {ConverterError}\r\n */\r\nasync function fetchRulesFromUrl(url) {\r\n  try {\r\n    if (!url || typeof url !== 'string') {\r\n      throw new ConverterError('无效的 URL', ERROR_CODES.INVALID_INPUT);\r\n    }\r\n\r\n    let parsedUrl;\r\n    try {\r\n      parsedUrl = new URL(url);\r\n    } catch {\r\n      throw new ConverterError('无效的 URL 格式', ERROR_CODES.INVALID_INPUT);\r\n    }\r\n\r\n    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {\r\n      throw new ConverterError('只支持 HTTP/HTTPS 协议', ERROR_CODES.INVALID_INPUT);\r\n    }\r\n\r\n    const response = await fetch(url, {\r\n      headers: { 'User-Agent': RULE_HUB_UA }\r\n    });\r\n\r\n    if (!response.ok) {\r\n      throw new ConverterError(\r\n        `HTTP ${response.status}: ${response.statusText}`,\r\n        ERROR_CODES.PARSE_ERROR\r\n      );\r\n    }\r\n\r\n    return await response.text();\r\n\r\n  } catch (error) {\r\n    if (error instanceof ConverterError) {\r\n      throw error;\r\n    }\r\n\r\n    throw new ConverterError(\r\n      `获取 URL 失败: ${error.message}`,\r\n      ERROR_CODES.PARSE_ERROR,\r\n      { url }\r\n    );\r\n  }\r\n}\r\n\r\n/**\r\n * 解析统计信息\r\n * @param {string} loonText - Loon 规则集文本\r\n * @returns {{ originalCount: number, convertedCount: number, unsupportedCount: number, timestamp: string }}\r\n */\r\nfunction parseStats(loonText) {\r\n  const lines = loonText.split('\\n');\r\n  const stats = {\r\n    originalCount: 0,\r\n    convertedCount: 0,\r\n    unsupportedCount: 0,\r\n    timestamp: ''\r\n  };\r\n\r\n  for (const line of lines) {\r\n    if (line.startsWith('# 原始规则数:')) {\r\n      stats.originalCount = parseInt(line.split(':')[1].trim(), 10);\r\n    } else if (line.startsWith('# 转换规则数:')) {\r\n      stats.convertedCount = parseInt(line.split(':')[1].trim(), 10);\r\n    } else if (line.startsWith('# 不支持规则数:')) {\r\n      stats.unsupportedCount = parseInt(line.split(':')[1].trim(), 10);\r\n    } else if (line.startsWith('# 生成时间:')) {\r\n      stats.timestamp = line.split(':').slice(1).join(':').trim();\r\n    }\r\n  }\r\n\r\n  return stats;\r\n}\n\n\n  // === 原生 JS UI 逻辑 ===\n  var inputMode = 'url';\n\n  function switchMode(mode) {\n    inputMode = mode;\n    var btns = document.querySelectorAll('.mode-btn');\n    for (var i = 0; i < btns.length; i++) {\n      btns[i].classList.toggle('active', btns[i].getAttribute('data-mode') === mode);\n    }\n    document.getElementById('url-input').style.display = mode === 'url' ? '' : 'none';\n    document.getElementById('text-input').style.display = mode === 'text' ? '' : 'none';\n  }\n\n  function showError(msg) {\n    document.getElementById('error-msg').textContent = msg;\n    document.getElementById('error-box').style.display = '';\n  }\n\n  function hideError() {\n    document.getElementById('error-box').style.display = 'none';\n  }\n\n  function showToast(msg) {\n    var el = document.getElementById('toast');\n    el.textContent = msg;\n    el.style.display = '';\n    setTimeout(function() { el.style.display = 'none'; }, 2000);\n  }\n\n  function setLoading(on) {\n    document.getElementById('loading').style.display = on ? '' : 'none';\n    document.getElementById('convertBtn').disabled = on;\n    document.getElementById('convertBtn').textContent = on ? '转换中...' : '开始转换';\n  }\n\n  function showResult(result) {\n    var stats = parseStats(result);\n    document.getElementById('stat-original').textContent = stats.originalCount;\n    document.getElementById('stat-converted').textContent = stats.convertedCount;\n    document.getElementById('stat-unsupported').textContent = stats.unsupportedCount;\n    document.getElementById('stats').style.display = '';\n    document.getElementById('outputText').value = result;\n    document.getElementById('output-card').style.display = '';\n    document.getElementById('copyLinkBtn').style.display = inputMode === 'url' ? '' : 'none';\n  }\n\n  function doConvert() {\n    hideError();\n    document.getElementById('output-card').style.display = 'none';\n    setLoading(true);\n\n    if (inputMode === 'url') {\n      var url = document.getElementById('inputUrl').value.trim();\n      if (!url) { showError('请输入 URL'); setLoading(false); return; }\n      // 通过 /convert 端点由脚本侧拉取（避免 CORS）\n      fetch('/convert?url=' + encodeURIComponent(url), { headers: { 'User-Agent': RULE_HUB_UA } })\n        .then(function(r) {\n          if (!r.ok) throw new Error('HTTP ' + r.status);\n          return r.text();\n        })\n        .then(function(text) { showResult(text); })\n        .catch(function(e) { showError('获取失败: ' + e.message); })\n        .finally(function() { setLoading(false); });\n    } else {\n      var text = document.getElementById('inputText').value.trim();\n      if (!text) { showError('请输入规则集'); setLoading(false); return; }\n      try {\n        var result = convertClashToLoon(text);\n        showResult(result);\n      } catch (e) {\n        showError(e.message);\n      }\n      setLoading(false);\n    }\n  }\n\n  function doCopy() {\n    var text = document.getElementById('outputText').value;\n    if (navigator.clipboard) {\n      navigator.clipboard.writeText(text).then(function() { showToast('已复制到剪贴板'); });\n    } else {\n      var ta = document.createElement('textarea');\n      ta.value = text;\n      document.body.appendChild(ta);\n      ta.select();\n      document.execCommand('copy');\n      document.body.removeChild(ta);\n      showToast('已复制到剪贴板');\n    }\n  }\n\n  function doCopyLink() {\n    var url = document.getElementById('inputUrl').value.trim();\n    if (!url) { showToast('无可用链接'); return; }\n    var link = location.origin + '/convert?url=' + encodeURIComponent(url);\n    if (navigator.clipboard) {\n      navigator.clipboard.writeText(link).then(function() { showToast('链接已复制到剪贴板'); });\n    } else {\n      var ta = document.createElement('textarea');\n      ta.value = link;\n      document.body.appendChild(ta);\n      ta.select();\n      document.execCommand('copy');\n      document.body.removeChild(ta);\n      showToast('链接已复制到剪贴板');\n    }\n  }\n\n  function doClear() {\n    document.getElementById('inputUrl').value = '';\n    document.getElementById('inputText').value = '';\n    document.getElementById('output-card').style.display = 'none';\n    document.getElementById('copyLinkBtn').style.display = 'none';\n    hideError();\n  }\n  </script>\n</body>\n</html>",
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      }
    }
  });
}
