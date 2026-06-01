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
    const _parseClashRules = typeof parseClashRules === 'function'
      ? parseClashRules
      : require('./clash-rules').parseClashRules;
    const _generateLoonRules = typeof generateLoonRules === 'function'
      ? generateLoonRules
      : require('./loon-rules').generateLoonRules;

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

// @BUILD:CUTOFF — 以下内容仅用于 Node/浏览器环境导出，构建 ui.js 时不包含

// 浏览器环境：挂载到 window
if (typeof window !== 'undefined') {
  window.convertClashToLoon = convertClashToLoon;
  window.fetchRulesFromUrl = fetchRulesFromUrl;
  window.parseStats = parseStats;
  window.ConverterError = ConverterError;
  window.ERROR_CODES = ERROR_CODES;
}

// CommonJS 导出（Jest 测试）
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    convertClashToLoon,
    fetchRulesFromUrl,
    parseStats,
    ConverterError,
    ERROR_CODES
  };
}
