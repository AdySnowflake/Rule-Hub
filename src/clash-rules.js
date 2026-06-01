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

// @BUILD:CUTOFF — 以下内容仅用于 Node/浏览器环境导出，构建 ui.js 时不包含

// 浏览器环境：挂载到 window
if (typeof window !== 'undefined') {
  window.detectFormat = detectFormat;
  window.parseClashRules = parseClashRules;
  window.parsePlainText = parsePlainText;
  window.parseRuleLine = parseRuleLine;
  window.parsePortRule = parsePortRule;
  window.extractSubRules = extractSubRules;
  window.parseLogicRule = parseLogicRule;
  window.inferRuleType = inferRuleType;
  window.isSupportedType = isSupportedType;
  window.cleanLine = cleanLine;
  window.restoreRegex = restoreRegex;
  window.SUPPORTED_TYPES = SUPPORTED_TYPES;
}

// CommonJS 导出（Jest 测试）
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    detectFormat,
    parseClashRules,
    parsePlainText,
    parseRuleLine,
    parsePortRule,
    extractSubRules,
    parseLogicRule,
    inferRuleType,
    isSupportedType,
    cleanLine,
    restoreRegex,
    SUPPORTED_TYPES
  };
}
