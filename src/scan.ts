import 'dotenv/config';
import { Octokit } from '@octokit/rest';
import { runOrchestrator } from './analyzer';
import { fetchPRDiff } from './github';
import chalk from 'chalk';

async function runCustomScan(owner: string, repo: string, prNumber: number) {
  console.log(`\n${chalk.cyan('[SentinAI]')} 📡 Fetching diff for ${owner}/${repo} PR #${prNumber}...`);

  try {
    const diff = await fetchPRDiff(owner, repo, prNumber);

    if (!diff || diff.trim().length === 0) {
      console.log(`${chalk.yellow('[Scout]')} ℹ️  Empty diff or could not fetch diff. Ensure GITHUB_TOKEN is set and PR exists.`);
      return;
    }

    console.log(`${chalk.green('[Scout]')} ✅ Diff fetched (${diff.length} characters). Starting analysis...`);

    const results = await runOrchestrator(diff, console.log);

    console.log(`\n${chalk.cyan('────────────────────────────────────────────────────────────')}\n`);

    if (!results || results.length === 0) {
      console.log(`${chalk.green('[Guardian]')} ✅ No vulnerabilities detected (or findings were below confidence threshold).`);
    } else {
      console.log(`\n${chalk.red.bold(`🚨 ${results.length} VULNERABILITY${results.length > 1 ? 'IES' : ''} DETECTED`)}`);

      for (let i = 0; i < results.length; i++) {
        const result = results[i];
        if (results.length > 1) {
          console.log(`\n${chalk.yellow.bold(`── Finding ${i + 1} of ${results.length} ────────────────────────────────`)}`);
        }
        console.log(`${chalk.bold('Vulnerability:')} ${result.vulnerability}`);
        console.log(`${chalk.bold('Severity:')}     ${result.severity}`);
        console.log(`${chalk.bold('Confidence:')}   ${result.confidence_score}%`);
        console.log(`${chalk.bold('OWASP:')}        ${result.owasp_category}`);
        console.log(`${chalk.bold('Endpoint:')}     ${result.affected_endpoint}`);
        console.log(`\n${chalk.bold('Reasoning:')}\n${result.reasoning}`);
        console.log(`\n${chalk.bold('Suggested Fix:')}\n${result.suggested_fix}`);
      }
    }

    console.log(`\n${chalk.cyan('────────────────────────────────────────────────────────────')}\n`);
  } catch (err) {
    console.error(`\n${chalk.red('[Error]')} Scan failed:`, err);
  }
}

// CLI Argument Parsing – accepts "owner/repo#pr" OR full GitHub URL
const args = process.argv.slice(2);
if (args.length !== 1) {
  console.error(`${chalk.red('Usage:')} npm run scan <owner/repo#pr_number> or full URL`);
  console.error(`${chalk.yellow('Example:')} npm run scan expressjs/express#42`);
  console.error(`${chalk.yellow('Example URL:')} npm run scan https://github.com/tokuhirom/mutsu/pull/1614`);
  process.exit(1);
}

let owner: string = '', repo: string = '', prNumber: number = 0;
const input = args[0];
if (input.startsWith('https://github.com/')) {
  const urlMatch = input.match(/^https:\/\/github\.com\/([^\/]+)\/([^\/]+)\/pull\/(\d+)/);
  if (!urlMatch) {
    console.error(chalk.red('Invalid GitHub URL format.'));
    process.exit(1);
  }
  owner = urlMatch[1];
  repo = urlMatch[2];
  prNumber = Number(urlMatch[3]);
} else {
  const shortMatch = input.match(/^([^\/]+)\/([^#]+)#(\d+)$/);
  if (!shortMatch) {
    console.error(chalk.red('Invalid format. Expected owner/repo#pr_number or full URL.'));
    process.exit(1);
  }
  owner = shortMatch[1];
  repo = shortMatch[2];
  prNumber = Number(shortMatch[3]);
}

if (!process.env.GITHUB_TOKEN) {
  console.warn(`${chalk.yellow('⚠️ warning:')} GITHUB_TOKEN is not set in .env. You may hit rate limits or be unable to scan private repos.`);
}

// Provider-aware key validation — only check the key required by the active provider
const activeProvider = (process.env.SENTINAI_PROVIDER || 'gemini').toLowerCase();

const providerKeyChecks: Record<string, { envVar: string; label: string }> = {
  gemini:     { envVar: 'GEMINI_API_KEY',    label: 'GEMINI_API_KEY' },
  vertex:     { envVar: 'GOOGLE_CLOUD_PROJECT', label: 'GOOGLE_CLOUD_PROJECT' },
  openai:     { envVar: 'OPENAI_API_KEY',    label: 'OPENAI_API_KEY' },
  anthropic:  { envVar: 'ANTHROPIC_API_KEY', label: 'ANTHROPIC_API_KEY' },
  // ollama is self-hosted — no API key required
};

const keyCheck = providerKeyChecks[activeProvider];
if (keyCheck && !process.env[keyCheck.envVar]) {
  console.error(`${chalk.red('❌ error:')} ${keyCheck.label} is missing from .env (required for SENTINAI_PROVIDER=${activeProvider}).`);
  process.exit(1);
}

runCustomScan(owner, repo, prNumber);
