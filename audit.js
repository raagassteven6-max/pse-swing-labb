#!/usr/bin/env node
/**
 * 🤖 PSE Swing Lab — AI Audit Swarm v1.0
 * Rule-based debugging & integrity engine for financial web apps
 * 
 * Usage:
 *   node audit.js --scan=static,security,performance,data
 *   node audit.js --file=index.html --output=report.json
 *   node audit.js --github-issue=true
 */

const fs = require('fs');
const path = require('path');

// ═══════════════════════════════════════════════════════════════════════════════
//  SWARM CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

const CONFIG = {
  version: '1.0.0',
  name: 'PSE Swing Lab Swarm',
  targetFile: process.argv.find(a => a.startsWith('--file='))?.split('=')[1] || 'index.html',
  outputFile: process.argv.find(a => a.startsWith('--output='))?.split('=')[1] || 'swarm-report.json',
  scans: (process.argv.find(a => a.startsWith('--scan='))?.split('=')[1] || 'all').split(','),
  createIssue: process.argv.includes('--github-issue=true'),
  severityWeights: { CRITICAL: 10, HIGH: 5, MEDIUM: 2, LOW: 1 },
  thresholds: {
    maxChartInstances: 2,
    maxResizeListeners: 3,
    apiTimeoutMs: 5000,
    frameBudgetMs: 33,
    longTaskMs: 200,
    memoryThreshold: 0.80
  }
};

// ═══════════════════════════════════════════════════════════════════════════════
//  AGENT DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════════════

class Agent {
  constructor(id, name, icon, rules) {
    this.id = id;
    this.name = name;
    this.icon = icon;
    this.rules = rules;
    this.findings = [];
  }

  scan(source, context = {}) {
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
        console.error(`[${this.id}] Rule ${rule.id} error:`, e.message);
      }
    }
    return this.findings;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AGENT 1: SECURITY AGENT 🛡️
// ═══════════════════════════════════════════════════════════════════════════════

const securityAgent = new Agent('security', 'Security Agent', '🛡️', [
  {
    id: 'S1.1',
    severity: 'CRITICAL',
    confidence: 0.95,
    message: 'Hardcoded API key/credential detected in source',
    check: (source) => {
      // Detect API keys, tokens, secrets
      const patterns = [
        { regex: /(apikey|api_key|token|secret|password|auth_token)\s*[:=]\s*['"`][a-zA-Z0-9_-]{16,}['"`]/gi, type: 'key-value' },
        { regex: /['"`][a-f0-9]{32}['"`]/gi, type: 'hex32' },
        { regex: /['"`][a-f0-9]{40}['"`]/gi, type: 'hex40' },
        { regex: /twelvedata.*['"`][a-zA-Z0-9]{32}['"`]/gi, type: 'twelve-data' }
      ];

      for (const p of patterns) {
        const matches = source.match(p.regex);
        if (matches && matches.length > 0) {
          // Filter false positives (CSS colors, common hashes)
          const suspicious = matches.filter(m => {
            const ctx = source.substring(Math.max(0, source.indexOf(m) - 50), source.indexOf(m) + m.length + 50);
            return /api|key|token|secret|auth|credential/i.test(ctx);
          });
          if (suspicious.length > 0) {
            return {
              found: true,
              message: `CRITICAL: Potential ${p.type} credential exposed (${suspicious.length} matches)`,
              evidence: suspicious.slice(0, 3),
              line: getLineNumber(source, suspicious[0])
            };
          }
        }
      }
      return { found: false };
    },
    fix: 'Move API keys to environment variables or a serverless proxy function'
  },
  {
    id: 'S1.2',
    severity: 'HIGH',
    confidence: 0.85,
    message: 'Potential XSS vector via innerHTML with user input',
    check: (source) => {
      // Find innerHTML assignments that include user input
      const innerHTMLPattern = /\.innerHTML\s*=\s*([^;]+)/g;
      const dangerousPattern = /[<>&"']|javascript:|on\w+\s*=/i;
      let match;
      const findings = [];

      while ((match = innerHTMLPattern.exec(source)) !== null) {
        const assignment = match[1];
        const line = getLineNumber(source, match[0]);

        // Check if assignment involves user input or dynamic content
        if (/customTicker|user|input|value|textContent/i.test(assignment) || dangerousPattern.test(assignment)) {
          findings.push({ assignment: assignment.trim().substring(0, 100), line });
        }
      }

      if (findings.length > 0) {
        return {
          found: true,
          message: `HIGH: ${findings.length} innerHTML assignment(s) with potential XSS risk`,
          evidence: findings,
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
      const hasCSPMeta = /meta[^>]*http-equiv=["']Content-Security-Policy["']/i.test(source);
      const hasCSPHeader = false; // Can't detect headers from source

      if (!hasCSPMeta) {
        return {
          found: true,
          message: 'MEDIUM: No Content Security Policy meta tag found',
          evidence: { hasCSPMeta, hasCSPHeader },
          line: null
        };
      }
      return { found: false };
    },
    fix: 'Add <meta http-equiv="Content-Security-Policy" content="default-src 'self' ...">'
  },
  {
    id: 'S1.4',
    severity: 'MEDIUM',
    confidence: 0.75,
    message: 'External scripts loaded without Subresource Integrity (SRI)',
    check: (source) => {
      const scriptPattern = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;
      let match;
      const withoutSRI = [];

      while ((match = scriptPattern.exec(source)) !== null) {
        const fullTag = match[0];
        const src = match[1];
        // Skip inline scripts and data URIs
        if (!src.startsWith('http') && !src.startsWith('//')) continue;
        // Check for integrity attribute
        if (!/integrity=["']/.test(fullTag)) {
          withoutSRI.push({ src, line: getLineNumber(source, fullTag) });
        }
      }

      if (withoutSRI.length > 0) {
        return {
          found: true,
          message: `MEDIUM: ${withoutSRI.length} external script(s) without SRI hash`,
          evidence: withoutSRI.map(s => s.src),
          line: withoutSRI[0].line
        };
      }
      return { found: false };
    },
    fix: 'Add integrity="sha384-..." to external script tags'
  }
]);

// ═══════════════════════════════════════════════════════════════════════════════
//  AGENT 2: MEMORY AGENT 🧠
// ═══════════════════════════════════════════════════════════════════════════════

const memoryAgent = new Agent('memory', 'Memory Agent', '🧠', [
  {
    id: 'M2.1',
    severity: 'HIGH',
    confidence: 0.90,
    message: 'Chart instance leak — createChart without matching remove()',
    check: (source) => {
      const createPattern = /createChart\s*\(/g;
      const removePattern = /\.remove\s*\(\s*\)/g;

      const creates = (source.match(createPattern) || []).length;
      const removes = (source.match(removePattern) || []).length;

      // Allow one extra create for initial setup
      if (creates > removes + 1) {
        return {
          found: true,
          message: `HIGH: Chart leak detected — ${creates} createChart() calls vs ${removes} remove() calls`,
          evidence: { creates, removes, leak: creates - removes },
          line: findFirstOccurrence(source, 'createChart')
        };
      }
      return { found: false };
    },
    fix: 'Call chart.remove() before creating a new chart instance'
  },
  {
    id: 'M2.2',
    severity: 'HIGH',
    confidence: 0.85,
    message: 'Event listener accumulation — resize listeners not removed',
    check: (source) => {
      const addPattern = /addEventListener\s*\(\s*['"]resize['"]/g;
      const removePattern = /removeEventListener\s*\(\s*['"]resize['"]/g;

      const adds = (source.match(addPattern) || []).length;
      const removes = (source.match(removePattern) || []).length;

      if (adds > removes + 2) {
        return {
          found: true,
          message: `HIGH: Resize listener leak — ${adds} addEventListener vs ${removes} removeEventListener`,
          evidence: { adds, removes, leak: adds - removes },
          line: findFirstOccurrence(source, 'addEventListener')
        };
      }
      return { found: false };
    },
    fix: 'Use ResizeObserver instead, or removeEventListener in cleanup'
  },
  {
    id: 'M2.3',
    severity: 'MEDIUM',
    confidence: 0.80,
    message: 'Object mutation in indicator calculations — side effects on source data',
    check: (source) => {
      // Check if calculate functions mutate the input array
      const mutatePattern = /function\s+calculate(EMA|SMA|RSI|VolumeSMA)[^}]*\{[^}]*for\s*\([^}]*data\[[^}]*\]\.[a-z]+\s*=/gi;
      const directAssign = /data\[i\]\.(ema20|sma50|rsi|volSMA)\s*=/g;

      const mutations = (source.match(directAssign) || []);

      if (mutations.length > 0) {
        return {
          found: true,
          message: `MEDIUM: ${mutations.length} direct mutation(s) of input data array detected`,
          evidence: mutations.slice(0, 5),
          line: findFirstOccurrence(source, 'data[i].ema20')
        };
      }
      return { found: false };
    },
    fix: 'Return new arrays instead of mutating input, or deep-clone before calculation'
  },
  {
    id: 'M2.4',
    severity: 'LOW',
    confidence: 0.60,
    message: 'Potential detached DOM nodes — innerHTML rebuilds without cleanup',
    check: (source) => {
      const innerHTMLPattern = /\.innerHTML\s*=/g;
      const count = (source.match(innerHTMLPattern) || []).length;

      if (count > 10) {
        return {
          found: true,
          message: `LOW: ${count} innerHTML assignments — potential for detached nodes`,
          evidence: { innerHTMLCount: count },
          line: null
        };
      }
      return { found: false };
    },
    fix: 'Use DocumentFragment for batch updates, or diff-based rendering'
  }
]);

// ═══════════════════════════════════════════════════════════════════════════════
//  AGENT 3: NETWORK AGENT 🌐
// ═══════════════════════════════════════════════════════════════════════════════

const networkAgent = new Agent('network', 'Network Agent', '🌐', [
  {
    id: 'N3.1',
    severity: 'HIGH',
    confidence: 0.90,
    message: 'Fetch without timeout — can hang indefinitely',
    check: (source) => {
      const fetchPattern = /fetch\s*\(/g;
      const fetchCalls = source.match(fetchPattern) || [];
      const abortPattern = /AbortController|signal|timeout/i;

      // Check if any fetch has timeout/abort handling
      const hasAbortHandling = abortPattern.test(source);

      if (fetchCalls.length > 0 && !hasAbortHandling) {
        return {
          found: true,
          message: `HIGH: ${fetchCalls.length} fetch() call(s) without timeout or AbortController`,
          evidence: { fetchCalls: fetchCalls.length, hasAbortHandling },
          line: findFirstOccurrence(source, 'fetch(')
        };
      }
      return { found: false };
    },
    fix: 'Wrap fetch in Promise.race with setTimeout, or use AbortController with signal'
  },
  {
    id: 'N3.2',
    severity: 'HIGH',
    confidence: 0.85,
    message: 'No retry logic for API failures',
    check: (source) => {
      const retryPattern = /retry|backoff|attempt|tries/i;
      const fetchPattern = /fetch\s*\(/g;

      const hasFetch = (source.match(fetchPattern) || []).length > 0;
      const hasRetry = retryPattern.test(source);

      if (hasFetch && !hasRetry) {
        return {
          found: true,
          message: 'HIGH: API calls without retry logic — transient failures will break app',
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
    message: 'No request deduplication — duplicate API calls waste quota',
    check: (source) => {
      const cachePattern = /cache|memo|dedup|pending/i;
      const fetchPattern = /fetch\s*\(/g;

      const hasFetch = (source.match(fetchPattern) || []).length > 0;
      const hasCache = cachePattern.test(source);

      if (hasFetch && !hasCache) {
        return {
          found: true,
          message: 'MEDIUM: No request caching/deduplication detected',
          evidence: { hasFetch, hasCache },
          line: null
        };
      }
      return { found: false };
    },
    fix: 'Cache responses by URL with TTL, or track pending requests to deduplicate'
  },
  {
    id: 'N3.4',
    severity: 'MEDIUM',
    confidence: 0.75,
    message: 'API error handling is generic — no specific status code handling',
    check: (source) => {
      const catchPattern = /\.catch\s*\(/g;
      const statusCheck = /r\.ok|r\.status|HTTP|status\s*===?\s*\d+/i;

      const catches = (source.match(catchPattern) || []).length;
      const hasStatusCheck = statusCheck.test(source);

      if (catches > 0 && !hasStatusCheck) {
        return {
          found: true,
          message: 'MEDIUM: Generic catch blocks without HTTP status inspection',
          evidence: { catchBlocks: catches, hasStatusCheck },
          line: findFirstOccurrence(source, '.catch(')
        };
      }
      return { found: false };
    },
    fix: 'Check response.ok and response.status before parsing (handle 429, 500, etc.)'
  }
]);

// ═══════════════════════════════════════════════════════════════════════════════
//  AGENT 4: STATE AGENT 📊
// ═══════════════════════════════════════════════════════════════════════════════

const stateAgent = new Agent('state', 'State Agent', '📊', [
  {
    id: 'ST4.1',
    severity: 'HIGH',
    confidence: 0.90,
    message: 'Race condition — load function callable while already loading',
    check: (source) => {
      // Check if there's a guard against concurrent execution
      const loadFuncPattern = /function\s+(loadStockData|runBacktest)/i;
      const guardPattern = /isLoading|disabled|pending|abort/i;

      const hasLoadFunc = loadFuncPattern.test(source);
      const hasGuard = guardPattern.test(source);

      if (hasLoadFunc && !hasGuard) {
        return {
          found: true,
          message: 'HIGH: No guard against concurrent execution of load functions',
          evidence: { hasLoadFunc, hasGuard },
          line: findFirstOccurrence(source, 'loadStockData')
        };
      }
      return { found: false };
    },
    fix: 'Set a loading flag at start, check it at entry, use AbortController for cancellation'
  },
  {
    id: 'ST4.2',
    severity: 'MEDIUM',
    confidence: 0.85,
    message: 'No data validation before chart rendering',
    check: (source) => {
      const setDataPattern = /setData\s*\(/g;
      const validationPattern = /if\s*\(\s*!data|data\.length|Array\.isArray|validate/i;

      const setDataCalls = (source.match(setDataPattern) || []).length;
      const hasValidation = validationPattern.test(source);

      if (setDataCalls > 0 && !hasValidation) {
        return {
          found: true,
          message: `MEDIUM: ${setDataCalls} setData() call(s) without prior data validation`,
          evidence: { setDataCalls, hasValidation },
          line: findFirstOccurrence(source, 'setData(')
        };
      }
      return { found: false };
    },
    fix: 'Validate data array length, required fields, and OHLC relationships before setData'
  },
  {
    id: 'ST4.3',
    severity: 'MEDIUM',
    confidence: 0.75,
    message: 'Global state variables — no encapsulation, prone to pollution',
    check: (source) => {
      const globalPattern = /^(let|var|const)\s+(currentMarket|currentTicker|currentData|chartInstance)\s*=/gm;
      const modulePattern = /export|import|module|class\s+App/i;

      const globals = (source.match(globalPattern) || []);
      const isModule = modulePattern.test(source);

      if (globals.length > 3 && !isModule) {
        return {
          found: true,
          message: `MEDIUM: ${globals.length} global state variables without module encapsulation`,
          evidence: globals.map(g => g.split('=')[0].trim()),
          line: null
        };
      }
      return { found: false };
    },
    fix: 'Wrap state in a module pattern or use ES6 modules with explicit exports'
  }
]);

// ═══════════════════════════════════════════════════════════════════════════════
//  AGENT 5: PERFORMANCE AGENT ⚡
// ═══════════════════════════════════════════════════════════════════════════════

const performanceAgent = new Agent('performance', 'Performance Agent', '⚡', [
  {
    id: 'P5.1',
    severity: 'MEDIUM',
    confidence: 0.80,
    message: 'Heavy calculations on main thread — no Web Worker offloading',
    check: (source) => {
      const calcPattern = /function\s+calculate(EMA|SMA|RSI|MACD|Bollinger)/i;
      const workerPattern = /Worker|webworker|worker\.js/i;

      const hasCalculations = calcPattern.test(source);
      const hasWorker = workerPattern.test(source);

      if (hasCalculations && !hasWorker) {
        return {
          found: true,
          message: 'MEDIUM: Technical indicator calculations run on main thread',
          evidence: { hasCalculations, hasWorker },
          line: findFirstOccurrence(source, 'calculateEMA')
        };
      }
      return { found: false };
    },
    fix: 'Move calculateEMA/SMA/RSI to a Web Worker for backtesting large datasets'
  },
  {
    id: 'P5.2',
    severity: 'MEDIUM',
    confidence: 0.70,
    message: 'No performance budget or metrics collection',
    check: (source) => {
      const perfPattern = /performance\.|PerformanceObserver|requestAnimationFrame|memory/i;
      const budgetPattern = /budget|threshold|limit|max.*ms/i;

      const hasPerf = perfPattern.test(source);
      const hasBudget = budgetPattern.test(source);

      if (!hasPerf || !hasBudget) {
        return {
          found: true,
          message: 'MEDIUM: No performance monitoring or budget enforcement',
          evidence: { hasPerf, hasBudget },
          line: null
        };
      }
      return { found: false };
    },
    fix: 'Add PerformanceObserver for long tasks, track frame times and memory usage'
  },
  {
    id: 'P5.3',
    severity: 'LOW',
    confidence: 0.65,
    message: 'Large table rebuilds — innerHTML for price table on every update',
    check: (source) => {
      const tablePattern = /getElementById\s*\(\s*['"]priceTableBody['"]\s*\)[^;]*\.innerHTML/g;
      const matches = source.match(tablePattern) || [];

      if (matches.length > 0) {
        return {
          found: true,
          message: `LOW: Price table rebuilt via innerHTML — inefficient for frequent updates`,
          evidence: { rebuildCount: matches.length },
          line: findFirstOccurrence(source, 'priceTableBody')
        };
      }
      return { found: false };
    },
    fix: 'Use DocumentFragment or diff-based updates; consider virtual scrolling for large datasets'
  }
]);

// ═══════════════════════════════════════════════════════════════════════════════
//  AGENT 6: DATA AGENT 📈
// ═══════════════════════════════════════════════════════════════════════════════

const dataAgent = new Agent('data', 'Data Agent', '📈', [
  {
    id: 'D6.1',
    severity: 'HIGH',
    confidence: 0.90,
    message: 'Missing data schema validation for API responses',
    check: (source) => {
      const parsePattern = /parseTwelveData|parseYahooData/i;
      const validatePattern = /validate|schema|required|typeof|Array\.isArray/i;

      const hasParser = parsePattern.test(source);
      const hasValidation = validatePattern.test(source);

      if (hasParser && !hasValidation) {
        return {
          found: true,
          message: 'HIGH: API response parsers without schema validation',
          evidence: { hasParser, hasValidation },
          line: findFirstOccurrence(source, 'parseTwelveData')
        };
      }
      return { found: false };
    },
    fix: 'Validate response shape: check for values array, required fields, data types'
  },
  {
    id: 'D6.2',
    severity: 'MEDIUM',
    confidence: 0.80,
    message: 'No handling for stock splits or reverse splits in price data',
    check: (source) => {
      const splitPattern = /split|adjust|dividend/i;
      const hasSplitHandling = splitPattern.test(source);

      if (!hasSplitHandling) {
        return {
          found: true,
          message: 'MEDIUM: No stock split detection — backtests may be inaccurate',
          evidence: { hasSplitHandling },
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
    message: 'Date handling may have timezone issues',
    check: (source) => {
      const datePattern = /toISOString\(\)|new Date\(\)/g;
      const tzPattern = /timezone|UTC|getTimezoneOffset|toLocaleString/i;

      const dateUses = (source.match(datePattern) || []).length;
      const hasTZHandling = tzPattern.test(source);

      if (dateUses > 5 && !hasTZHandling) {
        return {
          found: true,
          message: `MEDIUM: ${dateUses} date operations without explicit timezone handling`,
          evidence: { dateUses, hasTZHandling },
          line: findFirstOccurrence(source, 'toISOString')
        };
      }
      return { found: false };
    },
    fix: 'Use UTC for all date operations, or explicitly handle timezone offsets'
  },
  {
    id: 'D6.4',
    severity: 'LOW',
    confidence: 0.70,
    message: 'Mock data generator uses fixed seed — not truly random',
    check: (source) => {
      const mockPattern = /Math\.random\(\)/g;
      const seedPattern = /seed|randomSeed|crypto\.getRandomValues/i;

      const randomUses = (source.match(mockPattern) || []).length;
      const hasSeeding = seedPattern.test(source);

      if (randomUses > 0 && !hasSeeding) {
        return {
          found: true,
          message: `LOW: ${randomUses} Math.random() calls — consider seeded random for reproducible tests`,
          evidence: { randomUses, hasSeeding },
          line: null
        };
      }
      return { found: false };
    },
    fix: 'Use a seeded PRNG (e.g., mulberry32) for reproducible mock data in tests'
  }
]);

// ═══════════════════════════════════════════════════════════════════════════════
//  UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

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

function getHealthColor(health) {
  return health === 'healthy' ? '\x1b[32m' : health === 'degraded' ? '\x1b[33m' : '\x1b[31m';
}

function resetColor() { return '\x1b[0m'; }

// ═══════════════════════════════════════════════════════════════════════════════
//  REPORT GENERATORS
// ═══════════════════════════════════════════════════════════════════════════════

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
  let md = `# 🤖 PSE Swing Lab — Swarm Audit Report\n\n`;
  md += `**Generated:** ${new Date().toLocaleString()}\n`;
  md += `**File:** \`${CONFIG.targetFile}\` (${report.meta.linesOfCode.toLocaleString()} lines)\n`;
  md += `**Swarm Version:** ${CONFIG.version}\n\n`;

  md += `## 📊 Health Score: ${s.healthScore}/100\n\n`;

  md += `| Severity | Count | Status |\n`;
  md += `|----------|-------|--------|\n`;
  md += `| 🔴 Critical | ${s.critical} | ${s.critical > 0 ? '❌ FAIL' : '✅ PASS'} |\n`;
  md += `| 🟠 High | ${s.high} | ${s.high > 0 ? '⚠️ WARN' : '✅ PASS'} |\n`;
  md += `| 🟡 Medium | ${s.medium} | ${s.medium > 0 ? '⚠️ CHECK' : '✅ PASS'} |\n`;
  md += `| 🔵 Low | ${s.low} | ${s.low > 0 ? 'ℹ️ INFO' : '✅ PASS'} |\n`;
  md += `| **Auto-Fixable** | **${s.autoFixable}** | |\n\n`;

  if (s.critical > 0) {
    md += `## 🚨 CRITICAL — Immediate Action Required\n\n`;
    report.findings.filter(f => f.severity === 'CRITICAL').forEach((f, i) => {
      md += `### ${i + 1}. ${f.rule}: ${f.message}\n`;
      md += `- **Agent:** ${f.icon} ${f.agent}\n`;
      md += `- **Line:** ${f.line || 'N/A'}\n`;
      md += `- **Fix:** ${f.fix}\n`;
      if (f.evidence) md += `- **Evidence:** \`\`\`json\n${JSON.stringify(f.evidence, null, 2).substring(0, 300)}\n\`\`\`\n`;
      md += `\n`;
    });
  }

  if (s.high > 0) {
    md += `## 🟠 HIGH — Fix Before Next Deploy\n\n`;
    report.findings.filter(f => f.severity === 'HIGH').forEach((f, i) => {
      md += `### ${i + 1}. ${f.rule}: ${f.message}\n`;
      md += `- **Agent:** ${f.icon} ${f.agent}\n`;
      md += `- **Line:** ${f.line || 'N/A'}\n`;
      md += `- **Fix:** ${f.fix}\n\n`;
    });
  }

  if (s.medium > 0) {
    md += `## 🟡 MEDIUM — Address Soon\n\n`;
    report.findings.filter(f => f.severity === 'MEDIUM').forEach((f, i) => {
      md += `${i + 1}. **${f.rule}** — ${f.message}\n`;
      md += `   - Fix: ${f.fix}\n`;
    });
    md += `\n`;
  }

  if (s.low > 0) {
    md += `## 🔵 LOW — Nice to Have\n\n`;
    report.findings.filter(f => f.severity === 'LOW').forEach((f, i) => {
      md += `${i + 1}. **${f.rule}** — ${f.message}\n`;
    });
    md += `\n`;
  }

  md += `## 🛠️ Top Recommendations\n\n`;
  report.recommendations.forEach((r, i) => {
    md += `${i + 1}. **${r.priority}:** ${r.message}\n`;
  });

  md += `\n---\n`;
  md += `*Generated by PSE Swing Lab Swarm v${CONFIG.version}*\n`;

  return md;
}

function generateRecommendations(findings) {
  const priorityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

  // Group by fix message and pick highest severity
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

// ═══════════════════════════════════════════════════════════════════════════════
//  GITHUB ISSUE GENERATOR
// ═══════════════════════════════════════════════════════════════════════════════

function generateGitHubIssueBody(report) {
  const s = report.summary;
  let body = `## 🤖 Swarm Audit Alert\n\n`;
  body += `**Health Score:** ${s.healthScore}/100\n`;
  body += `**Findings:** ${s.critical} critical, ${s.high} high, ${s.medium} medium, ${s.low} low\n`;
  body += `**Auto-Fixable:** ${s.autoFixable}\n\n`;

  body += `### Critical Issues\n`;
  report.findings.filter(f => f.severity === 'CRITICAL').forEach(f => {
    body += `- **${f.rule}** (${f.agent}): ${f.message}\n`;
  });

  body += `\n### High Issues\n`;
  report.findings.filter(f => f.severity === 'HIGH').forEach(f => {
    body += `- **${f.rule}** (${f.agent}): ${f.message}\n`;
  });

  body += `\n### Recommendations\n`;
  report.recommendations.slice(0, 5).forEach(r => {
    body += `1. **[${r.priority}]** ${r.message}\n`;
  });

  body += `\n---\n*Run \`node ai-audit-swarm/audit.js\` locally for full details.*`;
  return body;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MAIN EXECUTION
// ═══════════════════════════════════════════════════════════════════════════════

function main() {
  console.log(`\n🤖 PSE Swing Lab — AI Audit Swarm v${CONFIG.version}\n`);

  // Check if target file exists
  if (!fs.existsSync(CONFIG.targetFile)) {
    console.error(`❌ File not found: ${CONFIG.targetFile}`);
    console.log(`   Run from repo root, or use --file=path/to/index.html`);
    process.exit(1);
  }

  const source = fs.readFileSync(CONFIG.targetFile, 'utf8');
  console.log(`📄 Scanning: ${CONFIG.targetFile} (${source.length.toLocaleString()} chars, ${source.split('\n').length} lines)\n`);

  // Run all agents
  const agents = [securityAgent, memoryAgent, networkAgent, stateAgent, performanceAgent, dataAgent];
  const allFindings = [];

  for (const agent of agents) {
    const findings = agent.scan(source);
    allFindings.push(...findings);

    const color = findings.length === 0 ? '\x1b[32m' : findings.some(f => f.severity === 'CRITICAL') ? '\x1b[31m' : '\x1b[33m';
    console.log(`${agent.icon} ${agent.name.padEnd(20)} ${color}${findings.length} findings${resetColor()}`);

    findings.forEach(f => {
      const sevColor = f.severity === 'CRITICAL' ? '\x1b[31m' : f.severity === 'HIGH' ? '\x1b[33m' : '\x1b[36m';
      console.log(`   ${sevColor}[${f.severity}]${resetColor()} ${f.rule}: ${f.message.substring(0, 80)}`);
    });
  }

  console.log(`\n${'─'.repeat(60)}`);

  // Generate report
  const report = generateJSONReport(allFindings, source);

  // Console summary
  const s = report.summary;
  const healthColor = s.healthScore >= 80 ? '\x1b[32m' : s.healthScore >= 50 ? '\x1b[33m' : '\x1b[31m';
  console.log(`\n📊 Health Score: ${healthColor}${s.healthScore}/100${resetColor()}`);
  console.log(`   🔴 Critical: ${s.critical}  🟠 High: ${s.high}  🟡 Medium: ${s.medium}  🔵 Low: ${s.low}`);
  console.log(`   🛠️  Auto-fixable: ${s.autoFixable}\n`);

  // Write JSON report
  fs.writeFileSync(CONFIG.outputFile, JSON.stringify(report, null, 2));
  console.log(`✅ Report saved: ${CONFIG.outputFile}`);

  // Write Markdown report
  const mdFile = CONFIG.outputFile.replace('.json', '.md');
  fs.writeFileSync(mdFile, generateMarkdownReport(report));
  console.log(`✅ Markdown saved: ${mdFile}`);

  // GitHub issue body (if requested)
  if (CONFIG.createIssue) {
    const issueFile = CONFIG.outputFile.replace('.json', '-issue.md');
    fs.writeFileSync(issueFile, generateGitHubIssueBody(report));
    console.log(`✅ Issue body saved: ${issueFile}`);
  }

  // Exit code based on severity
  if (s.critical > 0) {
    console.log(`\n❌ EXIT 1 — Critical issues found`);
    process.exit(1);
  } else if (s.high > 0) {
    console.log(`\n⚠️  EXIT 2 — High severity issues found`);
    process.exit(2);
  } else {
    console.log(`\n✅ All clear — no critical or high issues`);
    process.exit(0);
  }
}

// Run if called directly
if (require.main === module) {
  main();
}

// Export for testing
module.exports = { Agent, securityAgent, memoryAgent, networkAgent, stateAgent, performanceAgent, dataAgent, CONFIG };
