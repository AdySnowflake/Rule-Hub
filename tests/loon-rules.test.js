/**
 * Loon 规则生成器测试
 */

const {
  generateLoonRules,
  filterUnsupported,
  formatLoonRule,
  generateStatsHeader,
  TYPE_MAPPING
} = require('../src/loon-rules');

describe('filterUnsupported', () => {
  test('should filter unsupported rules', () => {
    const rules = [
      { type: 'DOMAIN', value: 'example.com', supported: true },
      { type: 'UNKNOWN', value: 'test', supported: false },
      { type: 'SCRIPT', value: 'test.js', supported: false }
    ];
    const filtered = filterUnsupported(rules);
    expect(filtered).toHaveLength(1);
    expect(filtered[0].type).toBe('DOMAIN');
  });

  test('should keep DST-PORT (mapped to DEST-PORT)', () => {
    const rules = [
      { type: 'DOMAIN', value: 'example.com', supported: true },
      { type: 'DST-PORT', value: '443', supported: true }
    ];
    const filtered = filterUnsupported(rules);
    expect(filtered).toHaveLength(2);
  });

  test('should keep all supported rules except Loon-unsupported', () => {
    const rules = [
      { type: 'DOMAIN', value: 'example.com', supported: true },
      { type: 'IP-CIDR', value: '192.168.0.0/16', supported: true }
    ];
    const filtered = filterUnsupported(rules);
    expect(filtered).toHaveLength(2);
  });
});

describe('formatLoonRule', () => {
  test('should format domain rule', () => {
    const rule = { type: 'DOMAIN', value: 'example.com', noResolve: '' };
    expect(formatLoonRule(rule)).toBe('DOMAIN,example.com');
  });

  test('should format IP-CIDR rule with no-resolve', () => {
    const rule = { type: 'IP-CIDR', value: '192.168.0.0/16', noResolve: ',no-resolve' };
    expect(formatLoonRule(rule)).toBe('IP-CIDR,192.168.0.0/16,no-resolve');
  });

  test('should format MATCH as FINAL', () => {
    const rule = { type: 'MATCH', value: 'DIRECT', noResolve: '' };
    expect(formatLoonRule(rule)).toBe('FINAL');
  });

  test('should return null for unknown type', () => {
    const rule = { type: 'UNKNOWN', value: 'test', noResolve: '' };
    expect(formatLoonRule(rule)).toBeNull();
  });
});

describe('generateStatsHeader', () => {
  test('should generate stats header', () => {
    const originalCount = 2;
    const convertedRules = ['DOMAIN,example.com'];
    const unsupportedRules = [];

    const header = generateStatsHeader(originalCount, convertedRules, unsupportedRules);

    expect(header).toContain('# Loon 规则集');
    expect(header).toContain('# 原始规则数: 2');
    expect(header).toContain('# 转换规则数: 1');
    expect(header).toContain('# 不支持规则数: 0');
  });
});

describe('generateLoonRules', () => {
  test('should generate complete Loon rules', () => {
    const rules = [
      { type: 'DOMAIN', value: 'example.com', supported: true, noResolve: '' },
      { type: 'IP-CIDR', value: '192.168.0.0/16', supported: true, noResolve: ',no-resolve' },
      { type: 'MATCH', value: 'DIRECT', supported: true, noResolve: '' }
    ];

    const output = generateLoonRules(rules);

    expect(output).toContain('DOMAIN,example.com');
    expect(output).toContain('IP-CIDR,192.168.0.0/16,no-resolve');
    expect(output).toContain('FINAL');
    expect(output).toContain('# 原始规则数: 3');
    expect(output).toContain('# 转换规则数: 3');
  });

  test('should convert DST-PORT to DEST-PORT in output', () => {
    const rules = [
      { type: 'DOMAIN', value: 'example.com', supported: true, noResolve: '' },
      { type: 'DST-PORT', value: '443', supported: true, noResolve: '' }
    ];

    const output = generateLoonRules(rules);

    expect(output).toContain('DOMAIN,example.com');
    expect(output).toContain('DEST-PORT,443');
    expect(output).not.toContain('DST-PORT,443');
  });

  test('should filter unsupported rules', () => {
    const rules = [
      { type: 'DOMAIN', value: 'example.com', supported: true, noResolve: '' },
      { type: 'UNKNOWN', value: 'test', supported: false, noResolve: '' }
    ];

    const output = generateLoonRules(rules);

    expect(output).toContain('DOMAIN,example.com');
    expect(output).toContain('# 不支持规则数: 1');
  });

  test('should handle empty rules', () => {
    const rules = [];
    const output = generateLoonRules(rules);

    expect(output).toContain('# 原始规则数: 0');
    expect(output).toContain('# 转换规则数: 0');
  });
});

describe('TYPE_MAPPING', () => {
  test('should have correct mappings', () => {
    expect(TYPE_MAPPING['DOMAIN']).toBe('DOMAIN');
    expect(TYPE_MAPPING['DOMAIN-SUFFIX']).toBe('DOMAIN-SUFFIX');
    expect(TYPE_MAPPING['IP-CIDR']).toBe('IP-CIDR');
    expect(TYPE_MAPPING['MATCH']).toBe('FINAL');
  });
});
