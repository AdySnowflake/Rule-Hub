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
  'MATCH': 'FINAL'
};

// Loon 不支持的规则类型（对齐原版 rule-parser.js Loon 分支的 other 过滤）
const LOON_UNSUPPORTED_TYPES = [
  'SCRIPT',
  'RULE-SET'
];

/**
 * 过滤不支持的规则（对齐原版 Loon 分支）
 * @param {Array<{ type: string, supported: boolean }>} rules - 规则数组
 * @returns {Array} 过滤后的规则
 */
function filterUnsupported(rules) {
  return rules.filter(rule => {
    if (!rule.supported) {
      return false;
    }

    // Loon 不支持的规则类型
    if (LOON_UNSUPPORTED_TYPES.includes(rule.type)) {
      return false;
    }

    return true;
  });
}

/**
 * 格式化单条 Loon 规则
 * @param {{ type: string, value: string, noResolve: string }} rule - 规则对象
 * @returns {string|null} 格式化后的规则字符串
 */
function formatLoonRule(rule) {
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
 * @param {Array} originalRules - 原始规则数组
 * @param {Array} convertedRules - 转换后的规则数组
 * @param {Array} unsupportedRules - 不支持的规则数组
 * @returns {string} 统计信息头
 */
function generateStatsHeader(originalRules, convertedRules, unsupportedRules) {
  const lines = [
    '# Loon 规则集',
    `# 生成时间: ${new Date().toISOString()}`,
    `# 原始规则数: ${originalRules.length}`,
    `# 转换规则数: ${convertedRules.length}`,
    `# 不支持规则数: ${unsupportedRules.length}`,
    ''
  ];

  return lines.join('\n');
}

/**
 * 生成 Loon 规则集
 * @param {Array<{ type: string, value: string, supported: boolean, noResolve: string }>} rules - 规则数组
 * @returns {string} Loon 规则集文本
 */
function generateLoonRules(rules) {
  const supportedRules = filterUnsupported(rules);
  const unsupportedRules = rules.filter(r => !r.supported || LOON_UNSUPPORTED_TYPES.includes(r.type));

  const loonRules = [];

  for (const rule of supportedRules) {
    const formatted = formatLoonRule(rule);
    if (formatted) {
      loonRules.push(formatted);
    }
  }

  const header = generateStatsHeader(rules, loonRules, unsupportedRules);

  return header + loonRules.join('\n');
}

// @BUILD:CUTOFF — 以下内容仅用于 Node/浏览器环境导出，构建 ui.js 时不包含

// 浏览器环境：挂载到 window
if (typeof window !== 'undefined') {
  window.generateLoonRules = generateLoonRules;
  window.filterUnsupported = filterUnsupported;
  window.formatLoonRule = formatLoonRule;
  window.generateStatsHeader = generateStatsHeader;
  window.TYPE_MAPPING = TYPE_MAPPING;
  window.LOON_UNSUPPORTED_TYPES = LOON_UNSUPPORTED_TYPES;
}

// CommonJS 导出（Jest 测试）
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    generateLoonRules,
    filterUnsupported,
    formatLoonRule,
    generateStatsHeader,
    TYPE_MAPPING,
    LOON_UNSUPPORTED_TYPES
  };
}
