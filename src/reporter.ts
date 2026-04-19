import { Octokit } from '@octokit/rest';
import { createHmac, timingSafeEqual } from 'crypto';
import { GuardianReport, ExploitStep } from './analyzer';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function severityBadge(severity: string): string {
  const badges: Record<string, string> = {
    CRITICAL: '🔴 CRITICAL',
    HIGH: '🟠 HIGH',
    MEDIUM: '🟡 MEDIUM',
    LOW: '🟢 LOW',
  };
  return badges[severity] ?? severity;
}

function confidenceBar(score: number): string {
  const filled = Math.round(score / 10);
  const bar = '█'.repeat(filled) + '░'.repeat(10 - filled);
  return `\`${bar}\` ${score}%`;
}

function formatExploitSteps(steps: ExploitStep[]): string {
  return steps
    .map((s) => {
      let block = `**Step ${s.step}:** ${s.action}`;
      if (s.request) {
        block += `\n\`\`\`http\n${s.request}\n\`\`\``;
      }
      block += `\n> **Response:** ${s.expected_response}`;
      return block;
    })
    .join('\n\n');
}

// ─── HMAC Feedback Signing ────────────────────────────────────────────────────

/**
 * Generate a HMAC-SHA256 signature for a feedback URL.
 * Message format: "<pr>:<type>" — ties the signature to both the PR number and feedback type.
 */
export function signFeedbackParams(pr: number, type: string): string {
  const secret = process.env.FEEDBACK_SECRET || 'sentinai-default-secret';
  return createHmac('sha256', secret).update(`${pr}:${type}`).digest('hex');
}

/**
 * Verify a feedback signature using a constant-time comparison to prevent timing attacks.
 * Returns true if the signature is valid and matches the expected value.
 */
export function verifyFeedbackSignature(pr: string, type: string, sig: string): boolean {
  if (!sig) return false;
  const secret = process.env.FEEDBACK_SECRET || 'sentinai-default-secret';
  const expected = createHmac('sha256', secret).update(`${pr}:${type}`).digest('hex');
  try {
    // Buffers must be equal length for timingSafeEqual — hex strings of the same hash algo always are
    return timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(sig, 'hex'));
  } catch {
    return false; // Malformed sig (wrong length) — reject
  }
}

// ─── Single finding formatter ─────────────────────────────────────────────────

function formatSingleFinding(report: GuardianReport, index: number, total: number): string {
  const header =
    total > 1
      ? `### Finding ${index + 1} of ${total} — ${report.vulnerability}`
      : `### 🚨 Vulnerability Detected`;

  return `${header}

| Field | Details |
|-------|---------|
| **Vulnerability** | ${report.vulnerability} |
| **Severity** | ${severityBadge(report.severity)} |
| **OWASP Category** | \`${report.owasp_category}\` |
| **Affected Endpoint** | \`${report.affected_endpoint}\` |
| **Confidence Score** | ${confidenceBar(report.confidence_score)} |

#### 🧠 Guardian's Analysis

${report.reasoning}

#### 🚨 Exploit Simulation

> *The Adversary agent simulated a real-world attack to confirm exploitability.*

${formatExploitSteps(report.exploit_simulation)}

#### ⚠️ False Positive Risk Assessment

> **${report.false_positive_risk}**

*The Guardian agent cross-referenced global middleware and framework-level protections before confirming this finding.*

#### 🔧 Suggested Remediation

\`\`\`typescript
${report.suggested_fix}
\`\`\``;
}

// ─── Full Report Formatter ────────────────────────────────────────────────────

export function formatMarkdownReport(reports: GuardianReport[], prNumber?: number): string {
  const timestamp = new Date().toISOString();
  const appId = process.env.APP_URL || 'http://localhost:3000';

  // Use the primary finding's OWASP category in the subtitle; fall back to a generic label for multi-finding
  const primaryCategory =
    reports.length === 1 ? reports[0].owasp_category : 'Multiple OWASP Categories';

  // Summary table for multi-finding reports
  const summaryTable =
    reports.length > 1
      ? `\n| # | Vulnerability | Severity | OWASP | Confidence |\n|---|--------------|----------|-------|------------|\n${reports
          .map(
            (r, i) =>
              `| ${i + 1} | ${r.vulnerability} | ${severityBadge(r.severity)} | \`${r.owasp_category}\` | ${r.confidence_score}% |`
          )
          .join('\n')}\n\n---\n`
      : '';

  const findingsBody = reports
    .map((r, i) => formatSingleFinding(r, i, reports.length))
    .join('\n\n---\n\n');

  const feedbackSection = prNumber
    ? `\n---\n\n### 🧠 Rate These Findings (Human-in-the-Loop)\n*Help SentinAI learn. Were these findings accurate?*\n[👍 True Positive](${appId}/api/feedback?pr=${prNumber}&type=tp&sig=${signFeedbackParams(prNumber, 'tp')})  |  [👎 False Positive - Ignore Future](${appId}/api/feedback?pr=${prNumber}&type=fp&sig=${signFeedbackParams(prNumber, 'fp')})`
    : '';

  return `## 🛡️ SentinAI Security Report

> *Autonomous AI-powered security analysis — ${primaryCategory} · Generated ${timestamp}*

---
${summaryTable}
${findingsBody}

---

### 🤖 Responsible AI Notice

This report was generated by **SentinAI** — a multi-agent AI system that combines an Architect (access control mapping), Adversary (red-team simulation), and Guardian (false positive validation) to surface real exploits with reduced noise.

A confidence score below 40% is automatically suppressed. Always review findings in the context of your full codebase before acting.

> *Powered by Google Gemini · [SentinAI](https://github.com/itxdeeni/SentinAI)*
${feedbackSection}`;
}

// ─── GitHub PR Comment ────────────────────────────────────────────────────────

export async function postPRComment(
  octokit: Octokit,
  owner: string,
  repo: string,
  prNumber: number,
  reports: GuardianReport[]
): Promise<void> {
  const body = formatMarkdownReport(reports, prNumber);

  // Look for an existing SentinAI comment to update rather than spamming new comments on re-scans
  const { data: comments } = await octokit.issues.listComments({
    owner,
    repo,
    issue_number: prNumber,
  });

  const existing = comments.find(
    (c) => c.body?.includes('## 🛡️ SentinAI Security Report')
  );

  if (existing) {
    await octokit.issues.updateComment({
      owner,
      repo,
      comment_id: existing.id,
      body,
    });
  } else {
    await octokit.issues.createComment({
      owner,
      repo,
      issue_number: prNumber,
      body,
    });
  }
}
