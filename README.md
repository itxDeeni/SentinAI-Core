# 🧩 SentinAI Core

**The open-source multi-agent security engine powering the SentinAI SaaS.**

SentinAI Core is an autonomous AI security auditor designed to reason about intended access rules, simulate real-world exploits, and identify logical flaws (like IDOR and BFL) that traditional static analysis tools miss.

## 🧠 Architecture: The Orchestration Loop

SentinAI uses a specialized three-agent pipeline powered by Google Gemini:

1.  **The Architect:** Maps the attack surface of a code diff, identifying routes, middleware, and potential data access points.
2.  **The Adversary:** Acts as a red-team researcher, cross-referencing findings with a RAG-based vulnerability memory to hypothesize specific exploit vectors.
3.  **The Guardian:** Evaluates findings against framework-level protections to suppress false positives and assign severity (LOW to CRITICAL).

## 🚀 Key Features

- **Multi-Agent Reasoning:** Context-aware security analysis.
- **Lethal Patterns:** Specialized in Business Logic Flaws (BFL) and Insecure Direct Object References (IDOR).
- **Hybrid Routing Support:** Optimized for running lightweight models (Flash Lite) for mapping and heavy models (Flash) for exploit reasoning.
- **Provider Agnostic:** Supports both **Google AI Studio** (local/dev) and **Vertex AI** (enterprise/production) via the Vercel AI SDK.

## 📦 Installation

```bash
# Add as a dependency to your Node.js project
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

## 🌐 Production Configuration (Vertex AI)

When deployed to Google Cloud Platform, SentinAI Core can be configured to use **Vertex AI** instead of the standard Google AI Studio. This provides enterprise-grade privacy and higher rate limits.

### Environment Variables

| Variable | Description |
| :--- | :--- |
| `GOOGLE_CLOUD_PROJECT` | Your GCP Project ID. Setting this triggers Vertex AI mode. |
| `GOOGLE_CLOUD_LOCATION` | (Optional) The region for Vertex AI (e.g., `us-central1`). |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to your service account JSON file (not needed on Cloud Run). |

### Vertex AI Privacy Guarantee
By using the `@ai-sdk/google-vertex` provider in production, SentinAI ensures that your source code diffs and analysis data are **never** used by Google to train foundation models.

---

## 🛡️ Responsible AI

- **Confidence Scoring:** Every finding includes a confidence threshold.
- **JSON Fallback:** Resilient parsing prevents pipeline crashes during LLM "hallucinations".
- **Context Awareness:** Understands middleware boundaries to reduce false positives.

## ⚖️ License

Apache 2.0. See [LICENSE](LICENSE) for details.
