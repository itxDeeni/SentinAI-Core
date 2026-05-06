# 🧩 SentinAI Core

**The open-source multi-agent security engine powering the SentinAI SaaS.**

SentinAI Core is an autonomous AI security auditor designed to reason about intended access rules, simulate real-world exploits, and identify logical flaws (like IDOR and BFL) that traditional static analysis tools miss.

## 🧠 Architecture: The Orchestration Loop

SentinAI uses a specialised three-agent pipeline that works with any supported LLM provider:

1.  **The Architect:** Maps the attack surface of a code diff, identifying routes, middleware, and potential data access points.
2.  **The Adversary:** Acts as a red-team researcher, cross-referencing findings with a RAG-based vulnerability memory to hypothesise specific exploit vectors.
3.  **The Guardian:** Evaluates findings against framework-level protections to suppress false positives and assign severity (LOW to CRITICAL).

## 🚀 Key Features

- **Multi-Agent Reasoning:** Context-aware security analysis that goes beyond pattern matching.
- **Lethal Patterns:** Specialised in Business Logic Flaws (BFL), OWASP Top 10, and Smart Contract vulnerabilities (Solana/Rust, EVM/Solidity, Aptos+Sui/Move).
- **Provider-Agnostic:** Swap AI backends with a single environment variable — no code changes required.
- **Zero-Leakage Mode:** Run entirely inside your own VPC with a self-hosted Ollama instance. Your source code never leaves your infrastructure.
- **Elite Tiered Routing:** Lightweight models handle fast diff mapping; heavy models handle exploit reasoning and final validation.

## 📦 Installation

```bash
npm install sentinai-core
```

## 🛠️ Usage

```typescript
import { runOrchestrator } from 'sentinai-core';

const diff = '... your github diff string ...';

// Custom logger to capture agent states
const logger = (msg: string) => console.log(msg);

const findings = await runOrchestrator(diff, logger);

console.log(`Detected ${findings.length} vulnerabilities.`);
```

---

## 🌐 Provider Configuration

Set `SENTINAI_PROVIDER` to select your AI backend. All other env vars for that provider become active.

### Gemini — Google AI Studio (default)

```env
SENTINAI_PROVIDER=gemini
GEMINI_API_KEY=your_key_here
```

Best for: local development, prototyping.

---

### Vertex AI — Google Cloud (enterprise)

```env
SENTINAI_PROVIDER=vertex
GOOGLE_CLOUD_PROJECT=your-gcp-project-id
GOOGLE_CLOUD_LOCATION=europe-west1   # optional, defaults shown
```

> **Privacy guarantee:** Vertex AI does not use your data for model training, and analysis never leaves your GCP project boundary.

| Variable | Description |
| :--- | :--- |
| `GOOGLE_CLOUD_PROJECT` | Your GCP Project ID |
| `GOOGLE_CLOUD_LOCATION` | Vertex AI region (default: `europe-west1`) |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service account JSON (not needed on Cloud Run) |

---

### Ollama — Self-Hosted / Zero-Leakage VPC

```env
SENTINAI_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434   # optional, defaults shown
OLLAMA_MODEL_LITE=qwen2.5-coder:7b      # Architect agent
OLLAMA_MODEL_PRO=qwen2.5-coder:14b     # Adversary agent
OLLAMA_MODEL_ELITE=deepseek-r1:32b     # Guardian agent
```

Ollama uses its OpenAI-compatible `/v1` endpoint under the hood, so no additional SDK is required.

> **Enterprise VPC deployment:** Point `OLLAMA_BASE_URL` at your internal Ollama host. Your PR diffs are analysed entirely within your private network — zero external API calls.

**Recommended models:**
| Tier | Default Model | Notes |
| :--- | :--- | :--- |
| Lite (Architect) | `qwen2.5-coder:7b` | Fast surface mapping |
| Pro (Adversary) | `qwen2.5-coder:14b` | Exploit reasoning |
| Elite (Guardian) | `deepseek-r1:32b` | Final validation |

---

### OpenAI

```env
SENTINAI_PROVIDER=openai
OPENAI_API_KEY=your_key_here
OPENAI_BASE_URL=                        # optional — override for Azure or compatible endpoints
OPENAI_MODEL_LITE=gpt-4o-mini           # optional, defaults shown
OPENAI_MODEL_PRO=gpt-4o
OPENAI_MODEL_ELITE=o3
```

---

### Anthropic

```env
SENTINAI_PROVIDER=anthropic
ANTHROPIC_API_KEY=your_key_here
ANTHROPIC_MODEL_LITE=claude-haiku-4-5   # optional, defaults shown
ANTHROPIC_MODEL_PRO=claude-sonnet-4-5
ANTHROPIC_MODEL_ELITE=claude-opus-4-5
```

---

## 📊 Environment Variable Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SENTINAI_PROVIDER` | `gemini` | Active AI provider: `gemini` \| `vertex` \| `ollama` \| `openai` \| `anthropic` |
| `MIN_CONFIDENCE` | `40` | Findings below this confidence % are suppressed |
| `GEMINI_API_KEY` | — | Required for `gemini` provider |
| `GOOGLE_CLOUD_PROJECT` | — | Required for `vertex` provider |
| `GOOGLE_CLOUD_LOCATION` | `europe-west1` | Vertex AI region |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama host URL |
| `OLLAMA_MODEL_LITE` | `qwen2.5-coder:7b` | Ollama model for Architect tier |
| `OLLAMA_MODEL_PRO` | `qwen2.5-coder:14b` | Ollama model for Adversary tier |
| `OLLAMA_MODEL_ELITE` | `deepseek-r1:32b` | Ollama model for Guardian tier |
| `OPENAI_API_KEY` | — | Required for `openai` provider |
| `OPENAI_BASE_URL` | — | Optional Azure / compatible endpoint override |
| `OPENAI_MODEL_LITE` | `gpt-4o-mini` | OpenAI model for Architect tier |
| `OPENAI_MODEL_PRO` | `gpt-4o` | OpenAI model for Adversary tier |
| `OPENAI_MODEL_ELITE` | `o3` | OpenAI model for Guardian tier |
| `ANTHROPIC_API_KEY` | — | Required for `anthropic` provider |
| `ANTHROPIC_MODEL_LITE` | `claude-haiku-4-5` | Anthropic model for Architect tier |
| `ANTHROPIC_MODEL_PRO` | `claude-sonnet-4-5` | Anthropic model for Adversary tier |
| `ANTHROPIC_MODEL_ELITE` | `claude-opus-4-5` | Anthropic model for Guardian tier |

---

## 🛡️ Responsible AI

- **Confidence Scoring:** Every finding includes a 0–100 confidence score; low-confidence findings are suppressed.
- **JSON Fallback:** Resilient three-strategy parsing prevents pipeline crashes during LLM hallucinations.
- **Context Awareness:** Understands middleware boundaries to reduce false positives.
- **Prompt Injection Guards:** All PR diffs are wrapped in `<source_diff_for_analysis>` tags and treated as untrusted data.
- **Exponential Backoff Retry:** All AI calls automatically retry up to 3 times (1s → 2s → 4s delay) on transient API errors (rate limits, 503s), ensuring reliability without manual intervention.
- **Graceful Pattern Fallback:** If `patterns.json` is missing or malformed at startup (e.g. before a build), the pipeline continues without the pattern library rather than crashing the process.

## ⚖️ License

Apache 2.0. See [LICENSE](LICENSE) for details.

> *Powered by SentinAI · [SentinAI-core](https://github.com/itxdeeni/sentinai-core)*

