/**
 * 转换主逻辑测试
 */

const {
  convertClashToLoon,
  parseStats,
  ConverterError,
  ERROR_CODES
} = require('../src/converter');

describe('convertClashToLoon', () => {
  test('should convert YAML format rules', () => {
    const input = `payload:
- DOMAIN-SUFFIX,example.com
- IP-CIDR,192.168.0.0/16,no-resolve
- MATCH,DIRECT`;

    const output = convertClashToLoon(input);

    expect(output).toContain('DOMAIN-SUFFIX,example.com');
    expect(output).toContain('IP-CIDR,192.168.0.0/16,no-resolve');
    expect(output).toContain('FINAL');
  });

  test('should convert plain text format rules', () => {
    const input = `DOMAIN-SUFFIX,example.com
IP-CIDR,192.168.0.0/16,no-resolve
MATCH,DIRECT`;

    const output = convertClashToLoon(input);

    expect(output).toContain('DOMAIN-SUFFIX,example.com');
    expect(output).toContain('IP-CIDR,192.168.0.0/16,no-resolve');
    expect(output).toContain('FINAL');
  });

  test('should throw error for null input', () => {
    expect(() => convertClashToLoon(null)).toThrow(ConverterError);
    expect(() => convertClashToLoon(null)).toThrow('无效的输入');
  });

  test('should throw error for empty input', () => {
    expect(() => convertClashToLoon('')).toThrow(ConverterError);
    expect(() => convertClashToLoon('')).toThrow('无效的输入');
  });

  test('should throw error for input with no rules', () => {
    expect(() => convertClashToLoon('# only comments')).toThrow(ConverterError);
    expect(() => convertClashToLoon('# only comments')).toThrow('未找到有效的规则');
  });

  test('should handle complex rules', () => {
    const input = `payload:
- DOMAIN,www.google.com
- DOMAIN-SUFFIX,google.com
- DOMAIN-KEYWORD,google
- IP-CIDR,192.168.0.0/16,no-resolve
- IP-CIDR6,fe80::/10
- GEOIP,CN
- DST-PORT,443
- SRC-PORT,8080
- MATCH,REJECT`;

    const output = convertClashToLoon(input);

    expect(output).toContain('DOMAIN,www.google.com');
    expect(output).toContain('DOMAIN-SUFFIX,google.com');
    expect(output).toContain('DOMAIN-KEYWORD,google');
    expect(output).toContain('IP-CIDR,192.168.0.0/16,no-resolve');
    expect(output).toContain('IP-CIDR6,fe80::/10');
    expect(output).toContain('GEOIP,CN');
    // DST-PORT should be converted to DEST-PORT
    expect(output).toContain('DEST-PORT,443');
    expect(output).not.toContain('DST-PORT,443');
    expect(output).toContain('SRC-PORT,8080');
    expect(output).toContain('FINAL');
  });

  test('should handle // inline comments', () => {
    const input = 'DOMAIN-SUFFIX,example.com // this is a comment';
    const output = convertClashToLoon(input);

    expect(output).toContain('DOMAIN-SUFFIX,example.com');
    expect(output).not.toContain('// this is a comment');
  });

  test('should handle spaced no-resolve', () => {
    const input = 'IP-CIDR,1.1.1.0/24, no-resolve';
    const output = convertClashToLoon(input);

    expect(output).toContain('IP-CIDR,1.1.1.0/24,no-resolve');
    expect(output).not.toContain(', no-resolve');
  });

  test('should handle case-insensitive NO-RESOLVE', () => {
    const input = 'IP-CIDR,10.0.0.0/8,NO-RESOLVE';
    const output = convertClashToLoon(input);

    expect(output).toContain('IP-CIDR,10.0.0.0/8,no-resolve');
  });

  test('should convert DST-PORT to DEST-PORT', () => {
    const input = `DST-PORT,443
DOMAIN,example.com`;

    const output = convertClashToLoon(input);

    expect(output).toContain('DEST-PORT,443');
    expect(output).not.toContain('DST-PORT,443');
    expect(output).toContain('DOMAIN,example.com');
  });

  test('should convert DST-PORT 多端口 / 为多条 DEST-PORT', () => {
    const input = 'DST-PORT,80/443/8080';
    const output = convertClashToLoon(input);

    expect(output).toContain('DEST-PORT,80');
    expect(output).toContain('DEST-PORT,443');
    expect(output).toContain('DEST-PORT,8080');
    expect(output).not.toContain('DST-PORT');
  });

  test('should convert DST-PORT 多端口 , 为多条 DEST-PORT', () => {
    const input = 'DST-PORT,80,443,8080';
    const output = convertClashToLoon(input);

    expect(output).toContain('DEST-PORT,80');
    expect(output).toContain('DEST-PORT,443');
    expect(output).toContain('DEST-PORT,8080');
  });

  test('should convert SRC-PORT 多端口', () => {
    const input = 'SRC-PORT,1024,2048';
    const output = convertClashToLoon(input);

    expect(output).toContain('SRC-PORT,1024');
    expect(output).toContain('SRC-PORT,2048');
  });

  test('should handle mixed port and domain rules', () => {
    const input = `DST-PORT,80/443
DOMAIN,example.com
DST-PORT,8080`;
    const output = convertClashToLoon(input);

    expect(output).toContain('DEST-PORT,80');
    expect(output).toContain('DEST-PORT,443');
    expect(output).toContain('DOMAIN,example.com');
    expect(output).toContain('DEST-PORT,8080');
  });

  test('should strip script/metadata lines', () => {
    const input = `DOMAIN,example.com
test-script.js enabled = true
IP-CIDR,192.168.0.0/16`;

    const output = convertClashToLoon(input);

    expect(output).toContain('DOMAIN,example.com');
    expect(output).toContain('IP-CIDR,192.168.0.0/16');
    expect(output).not.toContain('test-script.js');
  });

  test('should convert .prefix domain suffix', () => {
    const input = '.example.com';
    const output = convertClashToLoon(input);

    expect(output).toContain('DOMAIN-SUFFIX,example.com');
  });
});

describe('parseStats', () => {
  test('should parse stats from Loon text', () => {
    const loonText = `# Loon 规则集
# 生成时间: 2026-05-26T00:00:00.000Z
# 原始规则数: 100
# 转换规则数: 95
# 不支持规则数: 5

DOMAIN,example.com`;

    const stats = parseStats(loonText);

    expect(stats.originalCount).toBe(100);
    expect(stats.convertedCount).toBe(95);
    expect(stats.unsupportedCount).toBe(5);
    expect(stats.timestamp).toBe('2026-05-26T00:00:00.000Z');
  });

  test('should handle missing stats', () => {
    const loonText = 'DOMAIN,example.com';
    const stats = parseStats(loonText);

    expect(stats.originalCount).toBe(0);
    expect(stats.convertedCount).toBe(0);
    expect(stats.unsupportedCount).toBe(0);
  });
});

describe('ConverterError', () => {
  test('should create error with code', () => {
    const error = new ConverterError('test error', 'TEST_CODE');

    expect(error.message).toBe('test error');
    expect(error.code).toBe('TEST_CODE');
    expect(error.name).toBe('ConverterError');
  });

  test('should create error with details', () => {
    const details = { line: 10, content: 'test' };
    const error = new ConverterError('test error', 'TEST_CODE', details);

    expect(error.details).toEqual(details);
  });
});

describe('ERROR_CODES', () => {
  test('should have all error codes', () => {
    expect(ERROR_CODES.INVALID_INPUT).toBe('INVALID_INPUT');
    expect(ERROR_CODES.PARSE_ERROR).toBe('PARSE_ERROR');
    expect(ERROR_CODES.NO_RULES).toBe('NO_RULES');
    expect(ERROR_CODES.GENERATION_ERROR).toBe('GENERATION_ERROR');
  });
});
