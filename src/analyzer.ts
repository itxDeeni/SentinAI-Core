import { generateText } from 'ai';
import { createGoogleGenerativeAI } from '@ai-sdk/google';
import { createVertex } from '@ai-sdk/google-vertex';
import * as fs from 'fs';
import * as path from 'path';

function getModel(tier: 'pro' | 'lite' = 'pro') {
  if (process.env.NODE_ENV === 'production' || process.env.USE_VERTEX === 'true') {
    const vertex = createVertex({ 
      project: process.env.GOOGLE_CLOUD_PROJECT,
      location: process.env.GOOGLE_CLOUD_LOCATION || 'europe-west1'
    });
    // Use high-performance Flash Lite for the Architect to save costs
    const modelName = tier === 'lite' ? 'gemini-2.5-flash-lite-001' : 'gemini-2.5-flash-001';
    return vertex(modelName);
  }
  
  const google = createGoogleGenerativeAI({
    apiKey: process.env.GEMINI_API_KEY || '',
  });
  // Use 8b (Lite) for Architect, full Flash for reasoning tasks
  const modelName = tier === 'lite' ? 'gemini-1.5-flash-8b' : 'gemini-1.5-flash';
  return google(modelName);
}

export interface GuardianReport {
  vulnerability: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence_score: number;
  reasoning: string;
  false_positive_risk: string;
  owasp_category: string;
  exploit_simulation: ExploitStep[];
  affected_endpoint: string;
  suggested_fix: string;
}

export interface ExploitStep {
  step: number;
  action: string;
  request?: string;
  expected_response: string;
}

interface ArchitectReport {
  endpoints: string[];
  auth_middleware: string[];
  rbac_mapping: string;
  vulnerability_surface: string;
}

interface AdversaryReport {
  attack_vector: string;
  exploit_steps: ExploitStep[];
  bypass_technique: string;
  affected_endpoint: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

/** Hard cap on diff size sent to AI models — prevents context window overflow on large PRs. */
const MAX_DIFF_CHARS = 80_000;

const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

// ─── Pattern Loading ──────────────────────────────────────────────────────────

// Load and cache patterns once at module initialisation — no need to re-read disk on every request
function loadPatterns(): string {
  const patternsPath = path.join(__dirname, 'data', 'patterns.json');
  const raw = fs.readFileSync(patternsPath, 'utf-8');
  const patterns = JSON.parse(raw);
  return patterns
    .map(
      (p: { id: string; name: string; description: string; indicators: string[]; vulnerable_example: string }) =>
        `[${p.id}] ${p.name}\nDescription: ${p.description}\nIndicators: ${p.indicators.join(', ')}\nVulnerable Example:\n${p.vulnerable_example}`
    )
    .join('\n\n---\n\n');
}

const CACHED_PATTERNS: string = loadPatterns();

async function callAI(prompt: string, systemPrompt: string, tier: 'pro' | 'lite' = 'pro'): Promise<string> {
  const { text } = await generateText({
    model: getModel(tier),
    system: systemPrompt,
    prompt: prompt,
  });
  return text;
}

// ─── JSON Extraction ──────────────────────────────────────────────────────────

/**
 * Robustly extract a JSON value from an AI response using three fallback strategies:
 *   1. Direct JSON.parse — ideal path, no fences needed.
 *   2. Strip a single outermost ```json...``` or ```...``` fence (non-greedy) then parse.
 *   3. Walk the string to find and extract the first balanced { } or [ ] block.
 * Returns a parseable JSON string, or the literal string 'null' on total failure.
 */
function extractJSON(raw: string): string {
  const trimmed = raw.trim();

  // Strategy 1: Try parsing the raw response directly
  try {
    JSON.parse(trimmed);
    return trimmed;
  } catch { /* fall through */ }

  // Strategy 2: Strip a single outermost code fence (non-greedy inner match)
  const fenceMatch = trimmed.match(/^```(?:json)?\s*\n?([\s\S]*?)\n?```\s*$/i);
  if (fenceMatch) {
    const inner = fenceMatch[1].trim();
    try {
      JSON.parse(inner);
      return inner;
    } catch { /* fall through */ }
  }

  // Strategy 3: Find first balanced { ... } or [ ... ] block in the string
  const startIdx = trimmed.search(/[{[]/);
  if (startIdx !== -1) {
    const startChar = trimmed[startIdx];
    const endChar = startChar === '{' ? '}' : ']';
    let depth = 0;
    let endIdx = -1;
    for (let i = startIdx; i < trimmed.length; i++) {
      if (trimmed[i] === startChar) depth++;
      else if (trimmed[i] === endChar) {
        depth--;
        if (depth === 0) { endIdx = i; break; }
      }
    }
    if (endIdx !== -1) {
      const slice = trimmed.slice(startIdx, endIdx + 1);
      try {
        JSON.parse(slice);
        return slice;
      } catch { /* fall through */ }
    }
  }

  return 'null';
}

// ─── Agent 1: The Architect ──────────────────────────────────────────────────
async function runArchitect(diff: string, patterns: string, logger: (msg: string) => void): Promise<ArchitectReport> {
  logger('[Architect] 🏗️  Mapping access control topology and authentication middleware...');

  const systemPrompt = `You are a senior application security architect and smart contract auditor. Your role is to analyze code diffs and map out the intended access control, data flow, and state changes. You identify routes, functions, modifiers, middleware chains, and potential injection points. You respond ONLY with valid JSON — no markdown, no explanation.`;

  const prompt = `Analyze the following pull request diff. Cross-reference it against the known vulnerability patterns below.

== KNOWN VULNERABILITY PATTERNS (RAG Context) ==
${patterns}

== PULL REQUEST DIFF ==
${diff}

Map out:
1. All new or modified API endpoints, smart contract functions, or logic flows.
2. Authentication/authorization patterns, middleware, or smart contract modifiers present (or absent).
3. The intended RBAC model (who can access/call what).
4. The attack surface — specifically where user-supplied input flows into execution, DB access, or state changes without validation.

Respond with ONLY this JSON structure:
{
  "endpoints": ["GET /api/orders/:id", "Contract.withdraw()", "..."],
  "auth_middleware": ["isAuthenticated on /api/orders/:id", "onlyOwner on withdraw()", "MISSING checks", "..."],
  "rbac_mapping": "Summary of the intended role-based access control or modifier usage",
  "vulnerability_surface": "Precise description of where user input reaches data access/state changes without validation or where reentrancy/injection is possible"
}`;

  const raw = await callAI(prompt, systemPrompt, 'lite');
  logger('[Architect] ✅ Access control map complete');
  try {
    return JSON.parse(extractJSON(raw)) as ArchitectReport;
  } catch (err) {
    logger(`[Architect] ⚠️  Failed to parse JSON response — using partial surface from raw output: ${(err as Error).message}`);
    // Return a best-effort report so the pipeline can continue rather than crashing
    return {
      endpoints: [],
      auth_middleware: [],
      rbac_mapping: 'Unknown — AI response was not valid JSON',
      vulnerability_surface: raw.slice(0, 500),
    };
  }
}

// ─── Agent 2: The Adversary ──────────────────────────────────────────────────
async function runAdversary(
  diff: string,
  architectReport: ArchitectReport,
  patterns: string,
  logger: (msg: string) => void
): Promise<AdversaryReport[]> {
  logger('[Adversary] 🥷  Simulating attacks — probing all identified vulnerability surfaces...');

  const systemPrompt = `You are an elite red team security researcher and smart contract auditor. You think like an attacker. Your sole objective is to find ALL distinct, exploitable security vulnerabilities (Injection, SSRF, IDOR, Reentrancy, Logic Flaws, XSS, etc.) in code diffs. You craft realistic, step-by-step exploit scenarios for each. You MUST return a JSON array — never a bare object. If NO vulnerability is exploitable, return an empty array []. Respond ONLY with valid JSON — no markdown, no explanation.`;

  const prompt = `You have received the following intelligence from the Architect agent:

== ARCHITECT REPORT ==
Endpoints/Contracts: ${architectReport.endpoints.join(', ')}
Auth/Guards: ${architectReport.auth_middleware.join(', ')}
RBAC/Ownership Mapping: ${architectReport.rbac_mapping}
Vulnerability Surface: ${architectReport.vulnerability_surface}

== KNOWN VULNERABILITY PATTERNS (RAG Context) ==
${patterns}

== PULL REQUEST DIFF (Full Source) ==
${diff}

Your mission:
1. Identify ALL distinct, exploitable security vulnerabilities in this diff. Find up to 3; prioritise the most critical and severe.
2. For each, produce a precise, step-by-step exploit walkthrough. For web apps, show HTTP requests. For smart contracts, show transaction calls.
3. Describe the exact payload, variable manipulation, or malicious input an attacker would use.
4. Predict the response or state change that proves the exploit succeeds.

Return a JSON ARRAY of up to 3 findings, ordered most-severe first. If there are no vulnerabilities, return [].
Each item MUST have this shape:
{
  "attack_vector": "Parameter tampering on route ID / Mass assignment / Role escalation / etc.",
  "exploit_steps": [
    {
      "step": 1,
      "action": "Attacker authenticates as User A (ID: 101)",
      "request": "POST /api/auth/login {email: 'userA@test.com', password: '...'}",
      "expected_response": "200 OK, session token: JWT eyJ..."
    }
  ],
  "bypass_technique": "Direct object reference without ownership validation — the controller fetches by ID without comparing resource.userId to req.user.id",
  "affected_endpoint": "GET /api/orders/:id"
}

Return ONLY the JSON array, e.g.: [ {...}, {...} ] or []`;

  const raw = await callAI(prompt, systemPrompt, 'pro');
  const cleanRaw = extractJSON(raw);

  if (cleanRaw === 'null') {
    logger('[Adversary] 🔒 No exploitable vulnerabilities found in this diff');
    return [];
  }

  try {
    const parsed = JSON.parse(cleanRaw);
    // Gracefully handle a model that returns a single object instead of an array
    const results: AdversaryReport[] = Array.isArray(parsed) ? parsed : [parsed];
    if (results.length === 0) {
      logger('[Adversary] 🔒 No exploitable vulnerabilities found in this diff');
      return [];
    }
    logger(`[Adversary] 💥 Found ${results.length} potential exploit(s) — handing off to Guardian for validation`);
    return results;
  } catch (err) {
    logger(`[Adversary] ❌ Failed to parse JSON response: ${(err as Error).message}`);
    return [];
  }
}

// ─── Agent 3: The Guardian ───────────────────────────────────────────────────
async function runGuardian(
  diff: string,
  adversaryReport: AdversaryReport,
  architectReport: ArchitectReport,
  logger: (msg: string) => void
): Promise<GuardianReport> {
  logger(`[Guardian] 🛡️  Validating exploit on "${adversaryReport.affected_endpoint}" — checking for middleware and false positives...`);

  const systemPrompt = `You are a responsible AI security validation agent (The Guardian). Your job is to critically evaluate reported exploits and filter out false positives. You check for global middleware, framework-level protections, and logical errors in the adversary's reasoning. You are rigorous, skeptical, and precise. Respond ONLY with valid JSON — no markdown, no explanation. CRITICAL: never use triple backtick sequences inside JSON string values. In suggested_fix, write code as a plain string with \\n for newlines.`;

  const prompt = `You must validate the following exploit report produced by the Adversary agent.

== ARCHITECT REPORT (Access Control Map) ==
${JSON.stringify(architectReport, null, 2)}

== ADVERSARY EXPLOIT REPORT ==
${JSON.stringify(adversaryReport, null, 2)}

== FULL PR DIFF ==
${diff}

Your validation checklist:
1. Does any GLOBAL middleware (app.use()) apply to the affected route that would block the exploit?
2. Does a framework-level ORM/guard provide implicit ownership filtering?
3. Is the adversary's exploit logically consistent with the actual code in the diff?
4. Assign a confidence score 0–100 based on exploitability
5. Assign a severity: CRITICAL (auth bypass, full data access), HIGH (IDOR on sensitive data), MEDIUM (IDOR on non-sensitive), LOW (theoretical/requires chaining)
6. Provide a suggested code fix

Respond with ONLY this JSON:
{
  "vulnerability": "Short name, e.g. IDOR on Order endpoint",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW",
  "confidence_score": 91,
  "reasoning": "Detailed explanation of why this is a real vulnerability and not a false positive",
  "false_positive_risk": "Explanation of what could make this a false positive — e.g., upstream middleware not shown in diff",
  "owasp_category": "A01:2021 - Broken Access Control",
  "exploit_simulation": [
    {
      "step": 1,
      "action": "...",
      "request": "...",
      "expected_response": "..."
    }
  ],
  "affected_endpoint": "GET /api/orders/:id",
  "suggested_fix": "TypeScript/JS code snippet showing the secure version of the vulnerable code"
}`;

  const raw = await callAI(prompt, systemPrompt, 'pro');
  try {
    const report = JSON.parse(extractJSON(raw)) as GuardianReport;
    logger(`[Guardian] 📊 Confidence: ${report.confidence_score}% | Severity: ${report.severity} | FP Risk assessed`);
    return report;
  } catch (err) {
    logger(`[Guardian] ⚠️  Failed to parse JSON response — falling back to low-confidence rejection: ${(err as Error).message}`);
    // Return a low-confidence report so it gets filtered out gracefully, preventing pipeline crash
    return {
      vulnerability: 'Parsing Error',
      severity: 'LOW',
      confidence_score: 0,
      reasoning: 'The AI generated an invalid JSON response.',
      false_positive_risk: 'High risk due to parsing failure.',
      owasp_category: 'N/A',
      exploit_simulation: [],
      affected_endpoint: adversaryReport.affected_endpoint || 'Unknown',
      suggested_fix: '// Analysis failed',
    };
  }
}

// ─── Orchestrator ─────────────────────────────────────────────────────────────
/**
 * Runs the full multi-agent pipeline against a PR diff.
 * Returns an array of confirmed GuardianReports sorted by severity (CRITICAL first).
 * An empty array means the diff is clean or all findings were below the confidence threshold.
 */
export async function runOrchestrator(
  diff: string,
  logger: (msg: string) => void = console.log
): Promise<GuardianReport[]> {
  logger('[Orchestrator] 🚀 Dispatching multi-agent security pipeline...');

  // ── Diff size guard ──────────────────────────────────────────────────────────
  let safeDiff = diff;
  if (diff.length > MAX_DIFF_CHARS) {
    logger(
      `[Orchestrator] ⚠️  Diff is ${diff.length.toLocaleString()} chars — truncating to ${MAX_DIFF_CHARS.toLocaleString()} to stay within context limits. Large PRs may yield incomplete analysis.`
    );
    safeDiff =
      `[TRUNCATED — original diff was ${diff.length.toLocaleString()} chars; showing first ${MAX_DIFF_CHARS.toLocaleString()} chars only]\n\n` +
      diff.slice(0, MAX_DIFF_CHARS);
  }

  const patterns = CACHED_PATTERNS;

  // Step 1: Architect — map the attack surface
  const architectReport = await runArchitect(safeDiff, patterns, logger);

  // Step 2: Adversary — identify up to 3 distinct exploits
  const adversaryFindings = await runAdversary(safeDiff, architectReport, patterns, logger);
  if (adversaryFindings.length === 0) return [];

  // Step 3: Guardian — validate each finding independently
  const confirmedReports: GuardianReport[] = [];
  const minConfidence = parseInt(process.env.MIN_CONFIDENCE || '40', 10);
  
  for (const finding of adversaryFindings) {
    const guardianReport = await runGuardian(safeDiff, finding, architectReport, logger);
    if (guardianReport.confidence_score < minConfidence) {
      logger(
        `[Guardian] ⚠️  Low confidence (${guardianReport.confidence_score}% < ${minConfidence}%) on "${guardianReport.vulnerability}" — suppressing to reduce noise`
      );
      continue;
    }
    confirmedReports.push(guardianReport);
  }

  if (confirmedReports.length === 0) {
    logger(`[Orchestrator] 🔒 All findings suppressed (below ${minConfidence}% confidence threshold)`);
    return [];
  }

  // Sort by severity: CRITICAL → HIGH → MEDIUM → LOW
  confirmedReports.sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
  );

  logger(`[Orchestrator] ✅ Pipeline complete — ${confirmedReports.length} confirmed finding(s) — handing off to Reporter`);
  return confirmedReports;
}
