/**
 * Clash 规则解析器测试
 */

const {
  detectFormat,
  parseClashRules,
  parsePlainText,
  parseRuleLine,
  inferRuleType,
  isSupportedType,
  cleanLine
} = require('../src/clash-rules');

describe('detectFormat', () => {
  test('should detect YAML format with payload', () => {
    expect(detectFormat('payload:\n- DOMAIN-SUFFIX,example.com')).toBe('yaml');
  });

  test('should detect YAML format with dash prefix', () => {
    expect(detectFormat('- DOMAIN-SUFFIX,example.com')).toBe('yaml');
  });

  test('should detect plain text format', () => {
    expect(detectFormat('DOMAIN-SUFFIX,example.com')).toBe('plain');
  });
});

describe('cleanLine - 输入清洗对齐原版', () => {
  test('should strip payload: prefix', () => {
    const { cleaned } = cleanLine('payload:DOMAIN-SUFFIX,example.com');
    expect(cleaned).not.toContain('payload:');
  });

  test('should strip YAML list marker "- "', () => {
    const { cleaned } = cleanLine('- DOMAIN-SUFFIX,example.com');
    expect(cleaned).toContain('DOMAIN-SUFFIX');
    expect(cleaned).not.toMatch(/^- /);
  });

  test('should convert line-start // comment to #', () => {
    const { cleaned, isComment } = cleanLine('// this is a comment');
    expect(isComment).toBe(true);
    expect(cleaned).toMatch(/^#/);
  });

  test('should convert line-start ; comment to #', () => {
    const { cleaned, isComment } = cleanLine('; this is a comment');
    expect(isComment).toBe(true);
    expect(cleaned).toMatch(/^#/);
  });

  test('should strip inline // comment from non-comment line', () => {
    const { cleaned } = cleanLine('DOMAIN-SUFFIX,example.com // this is a comment');
    expect(cleaned).toContain('DOMAIN-SUFFIX,example.com');
    expect(cleaned).not.toContain('// this is a comment');
  });

  test('should strip script/metadata lines', () => {
    const { cleaned } = cleanLine('some-script.js enabled = true');
    expect(cleaned).toBe('');
  });

  test('should convert .example.com to DOMAIN-SUFFIX', () => {
    const { cleaned } = cleanLine('.example.com');
    expect(cleaned).toBe('DOMAIN-SUFFIX,example.com');
  });

  test('should convert *example.com to DOMAIN-SUFFIX', () => {
    const { cleaned } = cleanLine('*example.com');
    expect(cleaned).toBe('DOMAIN-SUFFIX,example.com');
  });

  test('should remove lines with regex quantifiers (metadata filter)', () => {
    // 原版 rule-parser.js 的元数据过滤器会移除包含 { 的行
    // 正则量词如 {1,2} 的规则不会被转换到 Loon
    const { cleaned } = cleanLine('DOMAIN-KEYWORD,test{1,2}');
    expect(cleaned).toBe('');
  });
});

describe('parseRuleLine - no-resolve 处理', () => {
  test('should parse no-resolve (standard)', () => {
    const rule = parseRuleLine('IP-CIDR,192.168.0.0/16,no-resolve');
    expect(rule.noResolve).toBe(',no-resolve');
  });

  test('should parse no-resolve with spaces', () => {
    const rule = parseRuleLine('IP-CIDR,1.1.1.0/24, no-resolve');
    expect(rule.noResolve).toBe(',no-resolve');
    expect(rule.value).toBe('1.1.1.0/24');
  });

  test('should parse NO-RESOLVE case-insensitive', () => {
    const rule = parseRuleLine('IP-CIDR,10.0.0.0/8,NO-RESOLVE');
    expect(rule.noResolve).toBe(',no-resolve');
  });

  test('should parse No-Resolve mixed case', () => {
    const rule = parseRuleLine('IP-CIDR,172.16.0.0/12,No-Resolve');
    expect(rule.noResolve).toBe(',no-resolve');
  });
});

describe('parseClashRules', () => {
  test('should parse YAML format', () => {
    const text = `payload:
- DOMAIN-SUFFIX,example.com
- IP-CIDR,192.168.0.0/16,no-resolve`;
    const rules = parseClashRules(text);

    expect(rules).toHaveLength(2);
    expect(rules[0]).toEqual({
      type: 'DOMAIN-SUFFIX',
      value: 'example.com',
      supported: true,
      noResolve: ''
    });
    expect(rules[1]).toEqual({
      type: 'IP-CIDR',
      value: '192.168.0.0/16',
      supported: true,
      noResolve: ',no-resolve'
    });
  });

  test('should parse plain text format', () => {
    const text = `DOMAIN-SUFFIX,example.com
IP-CIDR,192.168.0.0/16,no-resolve`;
    const rules = parseClashRules(text);
    expect(rules).toHaveLength(2);
  });

  test('should handle empty lines and comments', () => {
    const text = `# This is a comment

DOMAIN-SUFFIX,example.com

# Another comment`;
    const rules = parseClashRules(text);
    expect(rules).toHaveLength(1);
  });

  test('should handle // comments', () => {
    const text = `// this is a comment
DOMAIN-SUFFIX,example.com
// another comment`;
    const rules = parseClashRules(text);
    expect(rules).toHaveLength(1);
    expect(rules[0].type).toBe('DOMAIN-SUFFIX');
  });

  test('should strip inline // comments', () => {
    const text = 'DOMAIN-SUFFIX,example.com // inline comment';
    const rules = parseClashRules(text);
    expect(rules).toHaveLength(1);
    expect(rules[0].value).toBe('example.com');
    expect(rules[0].value).not.toContain('//');
  });

  test('should filter script/metadata lines', () => {
    const text = `DOMAIN-SUFFIX,example.com
some-script.js enabled = true
IP-CIDR,192.168.0.0/16`;
    const rules = parseClashRules(text);
    expect(rules).toHaveLength(2);
    expect(rules[0].type).toBe('DOMAIN-SUFFIX');
    expect(rules[1].type).toBe('IP-CIDR');
  });

  test('should parse DST-PORT as supported (converted to DEST-PORT for Loon)', () => {
    const text = 'DST-PORT,443';
    const rules = parseClashRules(text);
    expect(rules).toHaveLength(1);
    expect(rules[0].type).toBe('DST-PORT');
    expect(rules[0].supported).toBe(true);
  });

  test('should convert .prefix to DOMAIN-SUFFIX', () => {
    const text = '.example.com';
    const rules = parseClashRules(text);
    expect(rules).toHaveLength(1);
    expect(rules[0].type).toBe('DOMAIN-SUFFIX');
    expect(rules[0].value).toBe('example.com');
  });

  test('should infer type for domain', () => {
    const rules = parseClashRules('example.com');
    expect(rules[0].type).toBe('DOMAIN');
  });

  test('should infer type for IP', () => {
    const rules = parseClashRules('192.168.0.0/16');
    expect(rules[0].type).toBe('IP-CIDR');
  });

  test('should handle empty input', () => {
    expect(parseClashRules('')).toHaveLength(0);
    expect(parseClashRules(null)).toHaveLength(0);
  });

  test('should strip policy field from DOMAIN-SUFFIX rule', () => {
    const rules = parseClashRules('DOMAIN-SUFFIX,example.com,DIRECT');
    expect(rules).toHaveLength(1);
    expect(rules[0].type).toBe('DOMAIN-SUFFIX');
    expect(rules[0].value).toBe('example.com');
    expect(rules[0].value).not.toContain('DIRECT');
  });

  test('should strip policy field from IP-CIDR rule with no-resolve', () => {
    const rules = parseClashRules('IP-CIDR,10.0.0.0/8,Proxy,no-resolve');
    expect(rules).toHaveLength(1);
    expect(rules[0].type).toBe('IP-CIDR');
    expect(rules[0].value).toBe('10.0.0.0/8');
    expect(rules[0].value).not.toContain('Proxy');
    expect(rules[0].noResolve).toBe(',no-resolve');
  });

  test('should strip policy field from GEOIP rule', () => {
    const rules = parseClashRules('GEOIP,CN,DIRECT');
    expect(rules).toHaveLength(1);
    expect(rules[0].type).toBe('GEOIP');
    expect(rules[0].value).toBe('CN');
    expect(rules[0].value).not.toContain('DIRECT');
  });

  test('should handle MATCH,DIRECT correctly', () => {
    const rules = parseClashRules('MATCH,DIRECT');
    expect(rules).toHaveLength(1);
    expect(rules[0].type).toBe('MATCH');
    expect(rules[0].value).toBe('DIRECT');
  });
});

describe('inferRuleType', () => {
  test('should infer IPv4 address', () => {
    const rule = inferRuleType('192.168.0.0/16');
    expect(rule.type).toBe('IP-CIDR');
    expect(rule.supported).toBe(true);
  });

  test('should infer domain with TLD', () => {
    const rule = inferRuleType('example.com');
    expect(rule.type).toBe('DOMAIN');
    expect(rule.supported).toBe(true);
  });

  test('should infer keyword', () => {
    const rule = inferRuleType('google');
    expect(rule.type).toBe('DOMAIN-KEYWORD');
    expect(rule.supported).toBe(true);
  });

  test('should infer domain for ccTLD-like patterns', () => {
    // co.uk 有 2 字符 TLD，匹配 DOMAIN 规则
    const rule = inferRuleType('co.uk');
    expect(rule.type).toBe('DOMAIN');
    expect(rule.supported).toBe(true);
  });
});

describe('isSupportedType', () => {
  test('should return true for supported types', () => {
    expect(isSupportedType('DOMAIN')).toBe(true);
    expect(isSupportedType('DOMAIN-SUFFIX')).toBe(true);
    expect(isSupportedType('IP-CIDR')).toBe(true);
    expect(isSupportedType('MATCH')).toBe(true);
    expect(isSupportedType('DST-PORT')).toBe(true);
  });

  test('should return false for unsupported types', () => {
    expect(isSupportedType('SCRIPT')).toBe(false);
    expect(isSupportedType('RULE-SET')).toBe(false);
  });
});
