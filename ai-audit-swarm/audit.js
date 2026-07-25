#!/usr/bin/env node
/**
 * PSE Swing Lab - AI Audit Swarm v1.0
 * Rule-based debugging and integrity engine
 */

const fs = require('fs');
const path = require('path');

const CONFIG = {
  version: '1.0.0',
  name: 'PSE Swing Lab Swarm',
  targetFile: process.argv.find(a => a.startsWith('--file='))?.split('=')[1] || 'index.html',
  outputFile: process.argv.find(a => a.startsWith('--output='))?.split('=')[1] || 'swarm-report.json',
  createIssue: process.argv.includes('--github-issue=true'),
  severityWeights: { CRITICAL: 10, HIGH: 5, MEDIUM: 2, LOW: 1 }
};

class Agent {
  constructor(id, name, icon, rules) {
    this.id = id;
    this.name = name;
    this.icon = icon;
    this.rules = rules;
    this.findings = [];
  }

  scan(source, context) {
    this.findings = [];
    for (const rule of this.rules) {
      try {
        const result = rule.check(source, context);
        if (result.found) {
          this.findings.push({
            agent: this.id,
            agentName: this.name,
            icon: this.icon,
            rule: rule.id,
            severity: rule.severity,
            confidence: rule.confidence,
            message: result.message || rule.message,
            line: result.line || null,
            evidence: result.evidence || null,
            fix: rule.fix || null,
            autoFixable: !!rule.fix
          });
        }
      } catch (e) {
        console.error('[' + this.id + '] Rule ' + rule.id + ' error:', e.message);
      }
    }
    return this.findings;
  }
}

function getLineNumber(source, substring) {
  const index = source.indexOf(substring);
  if (index === -1) return null;
  return source.substring(0, index).split('\n').length;
}

function findFirstOccurrence(source, pattern) {
  const index = source.indexOf(pattern);
  if (index === -1) return null;
  return source.substring(0, index).split('\n').length;
}

function calculateScore(findings) {
  return findings.reduce((sum, f) => {
    const weight = CONFIG.severityWeights[f.severity] || 1;
    return sum + (weight * f.confidence);
  }, 0);
}

// ===== SECURITY AGENT =====
const securityAgent = new Agent('security', 'Security Agent', '🛡️', [
  {
    id: 'S1.1',
    severity: 'CRITICAL',
    confidence: 0.95,
    message: 'Hardcoded API key detected',
    check: (source) => {
      const keyPattern = /(apikey|api_key|token|secret|password|auth_token)\s*[:=]\s*['"`][a-zA-Z0-9_-]{16,}['"`]/gi;
      const matches = source.match(keyPattern);
      if (matches && matches.length > 0) {
        return {
          found: true,
          message: 'CRITICAL: Hardcoded API key/credential in source (' + matches.length + ' matches)',
          evidence: matches.slice(0, 3),
          line: getLineNumber(source, matches[0])
        };
      }
      return { found: false };
    },
    fix: 'Move API keys to environment variables or serverless proxy'
  },
  {
    id: 'S1.2',
    severity: 'HIGH',
    confidence: 0.85,
    message: 'XSS vector via innerHTML',
    check: (source) => {
      const pattern = /\.innerHTML\s*=/g;
      let match;
      const findings = [];
      while ((match = pattern.exec(source)) !== null) {
        const line = getLineNumber(source, match[0]);
        findings.push({ line });
      }
      if (findings.length > 0) {
        return {
          found: true,
          message: 'HIGH: ' + findings.length + ' innerHTML assignment(s) - potential XSS risk',
          evidence: { count: findings.length },
          line: findings[0].line
        };
      }
      return { found: false };
    },
    fix: 'Use textContent instead of innerHTML, or sanitize with DOMPurify'
  },
  {
    id: 'S1.3',
    severity: 'MEDIUM',
    confidence: 0.70,
    message: 'Missing Content Security Policy',
    check: (source) => {
      const hasCSP = /meta[^>]*http-equiv=["']Content-Security-Policy["']/i.test(source);
      if (!hasCSP) {
        return {
          found: true,
          message: 'MEDIUM: No Content Security Policy meta tag',
          evidence: { hasCSP: false },
          line: null
        };
      }
      return { found: false };
    },
    fix: 'Add CSP meta tag: <meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'
  },
  {
    id: 'S1.4',
    severity: 'MEDIUM',
    confidence: 0.75,
    message: 'External scripts without SRI',
    check: (source) => {
      const scriptPattern = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;
      let match;
      const withoutSRI = [];
      while ((match = scriptPattern.exec(source)) !== null) {
        const fullTag = match[0];
        const src = match[1];
        if (!src.startsWith('http') && !src.startsWith('//')) continue;
        if (!/integrity=["']/.test(fullTag)) {
          withoutSRI.push(src);
        }
      }
      if (withoutSRI.length > 0) {
        return {
          found: true,
          message: 'MEDIUM: ' + withoutSRI.length + ' external script(s) without SRI hash',
          evidence: withoutSRI,
          line: null
        };
      }
      return { found: false };
    },
    fix: 'Add integrity="sha384-..." to external script tags'
  }
]);

// ===== MEMORY AGENT =====
const memoryAgent = new Agent('memory', 'Memory Agent', '🧠', [
  {
    id: 'M2.1',
    severity: 'HIGH',
    confidence: 0.90,
    message: 'Chart instance leak',
    check: (source) => {
      const creates = (source.match(/createChart\s*\(/g) || []).length;
      const removes = (source.match(/\.remove\s*\(\s*\)/g) || []).length;
      if (creates > removes + 1) {
        return {
          found: true,
          message: 'HIGH: Chart leak - ' + creates + ' createChart() vs ' + removes + ' remove()',
          evidence: { creates, removes, leak: creates - removes },
          line: findFirstOccurrence(source, 'createChart')
        };
      }
      return { found: false };
    },
    fix: 'Call chart.remove() before creating new chart instance'
  },
  {
    id: 'M2.2',
    severity: 'HIGH',
    confidence: 0.85,
    message: 'Resize listener accumulation',
    check: (source) => {
      const adds = (source.match(/addEventListener\s*\(\s*['"]resize['"]/g) || []).length;
      const removes = (source.match(/removeEventListener\s*\(\s*['"]resize['"]/g) || []).length;
      if (adds > removes + 2) {
        return {
          found: true,
          message: 'HIGH: Resize listener leak - ' + adds + ' adds vs ' + removes + ' removes',
          evidence: { adds, removes, leak: adds - removes },
          line: findFirstOccurrence(source, 'addEventListener')
        };
      }
      return { found: false };
    },
    fix: 'Use ResizeObserver or removeEventListener in cleanup'
  },
  {
    id: 'M2.3',
    severity: 'MEDIUM',
    confidence: 0.80,
    message: 'Object mutation in calculations',
    check: (source) => {
      const pattern = /data\[i\]\.(ema20|sma50|rsi|volSMA)\s*=/g;
      const matches = source.match(pattern) || [];
      if (matches.length > 0) {
        return {
          found: true,
          message: 'MEDIUM: ' + matches.length + ' mutation(s) of input data array',
          evidence: matches.slice(0, 5),
          line: findFirstOccurrence(source, 'data[i].ema20')
        };
      }
      return { found: false };
    },
    fix: 'Return new arrays instead of mutating input, or deep-clone before calculation'
  }
]);

// ===== NETWORK AGENT =====
const networkAgent = new Agent('network', 'Network Agent', '🌐', [
  {
    id: 'N3.1',
    severity: 'HIGH',
    confidence: 0.90,
    message: 'Fetch without timeout',
    check: (source) => {
      const fetchCalls = (source.match(/fetch\s*\(/g) || []).length;
      const hasAbort = /AbortController|signal|timeout/i.test(source);
      if (fetchCalls > 0 && !hasAbort) {
        return {
          found: true,
          message: 'HIGH: ' + fetchCalls + ' fetch() call(s) without timeout/AbortController',
          evidence: { fetchCalls, hasAbort },
          line: findFirstOccurrence(source, 'fetch(')
        };
      }
      return { found: false };
    },
    fix: 'Wrap fetch in Promise.race with setTimeout, or use AbortController'
  },
  {
    id: 'N3.2',
    severity: 'HIGH',
    confidence: 0.85,
    message: 'No retry logic',
    check: (source) => {
      const hasFetch = /fetch\s*\(/g.test(source);
      const hasRetry = /retry|backoff|attempt|tries/i.test(source);
      if (hasFetch && !hasRetry) {
        return {
          found: true,
          message: 'HIGH: API calls without retry logic',
          evidence: { hasFetch, hasRetry },
          line: findFirstOccurrence(source, 'fetch(')
        };
      }
      return { found: false };
    },
    fix: 'Implement exponential backoff retry (1s, 2s, 4s) with max 3 attempts'
  },
  {
    id: 'N3.3',
    severity: 'MEDIUM',
    confidence: 0.80,
    message: 'No request deduplication',
    check: (source) => {
      const hasFetch = /fetch\s*\(/g.test(source);
      const hasCache = /cache|memo|dedup|pending/i.test(source);
      if (hasFetch && !hasCache) {
        return {
          found: true,
          message: 'MEDIUM: No request caching/deduplication',
          evidence: { hasFetch, hasCache },
          line: null
        };
      }
      return { found: false };
    },
    fix: 'Cache responses by URL with TTL, or track pending requests'
  }
]);

// ===== STATE AGENT =====
const stateAgent = new Agent('state', 'State Agent', '📊', [
  {
    id: 'ST4.1',
    severity: 'HIGH',
    confidence: 0.90,
    message: 'Race condition on load',
    check: (source) => {
      const hasLoad = /function\s+(loadStockData|runBacktest)/i.test(source);
      const hasGuard = /isLoading|disabled|pending|abort/i.test(source);
      if (hasLoad && !hasGuard) {
        return {
          found: true,
          message: 'HIGH: No guard against concurrent execution',
          evidence: { hasLoad, hasGuard },
          line: findFirstOccurrence(source, 'loadStockData')
        };
      }
      return { found: false };
    },
    fix: 'Set loading flag at start, check at entry, use AbortController'
  },
  {
    id: 'ST4.2',
    severity: 'MEDIUM',
    confidence: 0.85,
    message: 'No data validation before render',
    check: (source) => {
      const setDataCalls = (source.match(/setData\s*\(/g) || []).length;
      const hasValidation = /if\s*\(\s*!data|data\.length|Array\.isArray|validate/i.test(source);
      if (setDataCalls > 0 && !hasValidation) {
        return {
          found: true,
          message: 'MEDIUM: ' + setDataCalls + ' setData() without data validation',
          evidence: { setDataCalls, hasValidation },
          line: findFirstOccurrence(source, 'setData(')
        };
      }
      return { found: false };
    },
    fix: 'Validate data array length, required fields, OHLC relationships before setData'
  }
]);

// ===== PERFORMANCE AGENT =====
const performanceAgent = new Agent('performance', 'Performance Agent', '⚡', [
  {
    id: 'P5.1',
    severity: 'MEDIUM',
    confidence: 0.80,
    message: 'Heavy calculations on main thread',
    check: (source) => {
      const hasCalc = /function\s+calculate(EMA|SMA|RSI)/i.test(source);
      const hasWorker = /Worker|webworker/i.test(source);
      if (hasCalc && !hasWorker) {
        return {
          found: true,
          message: 'MEDIUM: Indicator calculations on main thread',
          evidence: { hasCalc, hasWorker },
          line: findFirstOccurrence(source, 'calculateEMA')
        };
      }
      return { found: false };
    },
    fix: 'Move calculateEMA/SMA/RSI to Web Worker for large datasets'
  },
  {
    id: 'P5.2',
    severity: 'MEDIUM',
    confidence: 0.70,
    message: 'No performance monitoring',
    check: (source) => {
      const hasPerf = /performance\.|PerformanceObserver|requestAnimationFrame/i.test(source);
      const hasBudget = /budget|threshold|limit|max.*ms/i.test(source);
      if (!hasPerf || !hasBudget) {
        return {
          found: true,
          message: 'MEDIUM: No performance monitoring or budget',
          evidence: { hasPerf, hasBudget },
          line: null
        };
      }
      return { found: false };
    },
    fix: 'Add PerformanceObserver for long tasks, track frame times'
  }
]);

// ===== DATA AGENT =====
const dataAgent = new Agent('data', 'Data Agent', '📈', [
  {
    id: 'D6.1',
    severity: 'HIGH',
    confidence: 0.90,
    message: 'Missing data schema validation',
    check: (source) => {
      const hasParser = /parseTwelveData|parseYahooData/i.test(source);
      const hasValidate = /validate|schema|required|typeof|Array\.isArray/i.test(source);
      if (hasParser && !hasValidate) {
        return {
          found: true,
          message: 'HIGH: API response parsers without schema validation',
          evidence: { hasParser, hasValidate },
          line: findFirstOccurrence(source, 'parseTwelveData')
        };
      }
      return { found: false };
    },
    fix: 'Validate response shape: check values array, required fields, data types'
  },
  {
    id: 'D6.2',
    severity: 'MEDIUM',
    confidence: 0.80,
    message: 'No stock split handling',
    check: (source) => {
      const hasSplit = /split|adjust|dividend/i.test(source);
      if (!hasSplit) {
        return {
          found: true,
          message: 'MEDIUM: No stock split detection - backtests may be inaccurate',
          evidence: { hasSplit },
          line: null
        };
      }
      return { found: false };
    },
    fix: 'Flag single-day >20% moves and check split history from API'
  },
  {
    id: 'D6.3',
    severity: 'MEDIUM',
    confidence: 0.75,
    message: 'Timezone issues in date handling',
    check: (source) => {
      const dateUses = (source.match(/toISOString\(\)|new Date\(\)/g) || []).length;
      const hasTZ = /timezone|UTC|getTimezoneOffset/i.test(source);
      if (dateUses > 5 && !hasTZ) {
        return {
          found: true,
          message: 'MEDIUM: ' + dateUses + ' date operations without timezone handling',
          evidence: { dateUses, hasTZ },
          line: findFirstOccurrence(source, 'toISOString')
        };
      }
      return { found: false };
    },
    fix: 'Use UTC for all date operations, or handle timezone offsets explicitly'
  }
]);

// ===== REPORT GENERATORS =====

function generateJSONReport(allFindings, source) {
  const bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
  allFindings.forEach(f => {
    if (bySeverity[f.severity]) bySeverity[f.severity].push(f);
  });

  return {
    meta: {
      version: CONFIG.version,
      name: CONFIG.name,
      timestamp: new Date().toISOString(),
      fileScanned: CONFIG.targetFile,
      fileSize: source.length,
      linesOfCode: source.split('\n').length
    },
    summary: {
      totalFindings: allFindings.length,
      critical: bySeverity.CRITICAL.length,
      high: bySeverity.HIGH.length,
      medium: bySeverity.MEDIUM.length,
      low: bySeverity.LOW.length,
      autoFixable: allFindings.filter(f => f.autoFixable).length,
      healthScore: Math.max(0, 100 - calculateScore(allFindings)).toFixed(1)
    },
    agents: [
      { id: 'security', name: 'Security Agent', icon: '🛡️', findings: allFindings.filter(f => f.agent === 'security') },
      { id: 'memory', name: 'Memory Agent', icon: '🧠', findings: allFindings.filter(f => f.agent === 'memory') },
      { id: 'network', name: 'Network Agent', icon: '🌐', findings: allFindings.filter(f => f.agent === 'network') },
      { id: 'state', name: 'State Agent', icon: '📊', findings: allFindings.filter(f => f.agent === 'state') },
      { id: 'performance', name: 'Performance Agent', icon: '⚡', findings: allFindings.filter(f => f.agent === 'performance') },
      { id: 'data', name: 'Data Agent', icon: '📈', findings: allFindings.filter(f => f.agent === 'data') }
    ],
    findings: allFindings.map(f => ({
      rule: f.rule,
      agent: f.agentName,
      icon: f.icon,
      severity: f.severity,
      confidence: f.confidence,
      message: f.message,
      line: f.line,
      evidence: f.evidence,
      fix: f.fix,
      autoFixable: f.autoFixable
    })),
    recommendations: generateRecommendations(allFindings)
  };
}

function generateMarkdownReport(report) {
  const s = report.summary;
  let md = '# 🤖 PSE Swing Lab - Swarm Audit Report\n\n';
  md += '**Generated:** ' + new Date().toLocaleString() + '\n';
  md += '**File:** `' + CONFIG.targetFile + '` (' + report.meta.linesOfCode.toLocaleString() + ' lines)\n';
  md += '**Swarm Version:** ' + CONFIG.version + '\n\n';

  md += '## Health Score: ' + s.healthScore + '/100\n\n';

  md += '| Severity | Count | Status |\n';
  md += '|----------|-------|--------|\n';
  md += '| 🔴 Critical | ' + s.critical + ' | ' + (s.critical > 0 ? '❌ FAIL' : '✅ PASS') + ' |\n';
  md += '| 🟠 High | ' + s.high + ' | ' + (s.high > 0 ? '⚠️ WARN' : '✅ PASS') + ' |\n';
  md += '| 🟡 Medium | ' + s.medium + ' | ' + (s.medium > 0 ? '⚠️ CHECK' : '✅ PASS') + ' |\n';
  md += '| 🔵 Low | ' + s.low + ' | ' + (s.low > 0 ? 'ℹ️ INFO' : '✅ PASS') + ' |\n';
  md += '| **Auto-Fixable** | **' + s.autoFixable + '** | |\n\n';

  if (s.critical > 0) {
    md += '## 🚨 CRITICAL - Immediate Action Required\n\n';
    report.findings.filter(f => f.severity === 'CRITICAL').forEach((f, i) => {
      md += '### ' + (i + 1) + '. ' + f.rule + ': ' + f.message + '\n';
      md += '- **Agent:** ' + f.icon + ' ' + f.agent + '\n';
      md += '- **Line:** ' + (f.line || 'N/A') + '\n';
      md += '- **Fix:** ' + f.fix + '\n\n';
    });
  }

  if (s.high > 0) {
    md += '## 🟠 HIGH - Fix Before Next Deploy\n\n';
    report.findings.filter(f => f.severity === 'HIGH').forEach((f, i) => {
      md += '### ' + (i + 1) + '. ' + f.rule + ': ' + f.message + '\n';
      md += '- **Agent:** ' + f.icon + ' ' + f.agent + '\n';
      md += '- **Line:** ' + (f.line || 'N/A') + '\n';
      md += '- **Fix:** ' + f.fix + '\n\n';
    });
  }

  if (s.medium > 0) {
    md += '## 🟡 MEDIUM - Address Soon\n\n';
    report.findings.filter(f => f.severity === 'MEDIUM').forEach((f, i) => {
      md += (i + 1) + '. **' + f.rule + '** - ' + f.message + '\n';
      md += '   - Fix: ' + f.fix + '\n';
    });
    md += '\n';
  }

  md += '## 🛠️ Top Recommendations\n\n';
  report.recommendations.forEach((r, i) => {
    md += (i + 1) + '. **[' + r.priority + ']** ' + r.message + '\n';
  });

  md += '\n---\n';
  md += '*Generated by PSE Swing Lab Swarm v' + CONFIG.version + '*\n';

  return md;
}

function generateGitHubIssueBody(report) {
  const s = report.summary;
  let body = '## 🤖 Swarm Audit Alert\n\n';
  body += '**Health Score:** ' + s.healthScore + '/100\n';
  body += '**Findings:** ' + s.critical + ' critical, ' + s.high + ' high, ' + s.medium + ' medium, ' + s.low + ' low\n';
  body += '**Auto-Fixable:** ' + s.autoFixable + '\n\n';

  body += '### Critical Issues\n';
  report.findings.filter(f => f.severity === 'CRITICAL').forEach(f => {
    body += '- **' + f.rule + '** (' + f.agent + '): ' + f.message + '\n';
  });

  body += '\n### High Issues\n';
  report.findings.filter(f => f.severity === 'HIGH').forEach(f => {
    body += '- **' + f.rule + '** (' + f.agent + '): ' + f.message + '\n';
  });

  body += '\n### Recommendations\n';
  report.recommendations.slice(0, 5).forEach(r => {
    body += '1. **[' + r.priority + ']** ' + r.message + '\n';
  });

  body += '\n---\n*Run `node ai-audit-swarm/audit.js` locally for full details.*';
  return body;
}

function generateRecommendations(findings) {
  const priorityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const fixMap = new Map();

  findings.forEach(f => {
    if (!f.fix) return;
    const existing = fixMap.get(f.fix);
    if (!existing || priorityOrder[f.severity] < priorityOrder[existing.severity]) {
      fixMap.set(f.fix, f);
    }
  });

  return Array.from(fixMap.values())
    .sort((a, b) => priorityOrder[a.severity] - priorityOrder[b.severity])
    .slice(0, 10)
    .map(f => ({
      priority: f.severity,
      message: f.fix,
      rule: f.rule,
      agent: f.agentName
    }));
}

// ===== MAIN =====

function main() {
  console.log('\n🤖 PSE Swing Lab - AI Audit Swarm v' + CONFIG.version + '\n');

  if (!fs.existsSync(CONFIG.targetFile)) {
    console.error('❌ File not found: ' + CONFIG.targetFile);
    console.log('   Run from repo root, or use --file=path/to/index.html');
    process.exit(1);
  }

  const source = fs.readFileSync(CONFIG.targetFile, 'utf8');
  console.log('📄 Scanning: ' + CONFIG.targetFile + ' (' + source.length.toLocaleString() + ' chars, ' + source.split('\n').length + ' lines)\n');

  const agents = [securityAgent, memoryAgent, networkAgent, stateAgent, performanceAgent, dataAgent];
  const allFindings = [];

  for (const agent of agents) {
    const findings = agent.scan(source);
    allFindings.push(...findings);

    const color = findings.length === 0 ? '\x1b[32m' : findings.some(f => f.severity === 'CRITICAL') ? '\x1b[31m' : '\x1b[33m';
    const reset = '\x1b[0m';
    console.log(agent.icon + ' ' + agent.name.padEnd(20) + ' ' + color + findings.length + ' findings' + reset);

    findings.forEach(f => {
      const sevColor = f.severity === 'CRITICAL' ? '\x1b[31m' : f.severity === 'HIGH' ? '\x1b[33m' : '\x1b[36m';
      console.log('   ' + sevColor + '[' + f.severity + ']' + reset + ' ' + f.rule + ': ' + f.message.substring(0, 80));
    });
  }

  console.log('\n' + '─'.repeat(60));

  const report = generateJSONReport(allFindings, source);
  const s = report.summary;
  const healthColor = s.healthScore >= 80 ? '\x1b[32m' : s.healthScore >= 50 ? '\x1b[33m' : '\x1b[31m';
  const reset = '\x1b[0m';

  console.log('\n📊 Health Score: ' + healthColor + s.healthScore + '/100' + reset);
  console.log('   🔴 Critical: ' + s.critical + '  🟠 High: ' + s.high + '  🟡 Medium: ' + s.medium + '  🔵 Low: ' + s.low);
  console.log('   🛠️  Auto-fixable: ' + s.autoFixable + '\n');

  fs.writeFileSync(CONFIG.outputFile, JSON.stringify(report, null, 2));
  console.log('✅ Report saved: ' + CONFIG.outputFile);

  const mdFile = CONFIG.outputFile.replace('.json', '.md');
  fs.writeFileSync(mdFile, generateMarkdownReport(report));
  console.log('✅ Markdown saved: ' + mdFile);

  if (CONFIG.createIssue) {
    const issueFile = CONFIG.outputFile.replace('.json', '-issue.md');
    fs.writeFileSync(issueFile, generateGitHubIssueBody(report));
    console.log('✅ Issue body saved: ' + issueFile);
  }

  if (s.critical > 0) {
    console.log('\n❌ EXIT 1 - Critical issues found');
    process.exit(1);
  } else if (s.high > 0) {
    console.log('\n⚠️  EXIT 2 - High severity issues found');
    process.exit(2);
  } else {
    console.log('\n✅ All clear - no critical or high issues');
    process.exit(0);
  }
}

if (require.main === module) {
  main();
}

module.exports = { Agent, securityAgent, memoryAgent, networkAgent, stateAgent, performanceAgent, dataAgent, CONFIG };
