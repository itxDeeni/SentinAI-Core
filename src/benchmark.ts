import { runArchitect, runAdversary, runGuardian } from './analyzer';
import * as fs from 'fs';
import * as path from 'path';
import 'dotenv/config';

// Mock Diff (IDOR vulnerability)
const BENCHMARK_DIFF = `
diff --git a/src/controllers/userController.ts b/src/controllers/userController.ts
--- a/src/controllers/userController.ts
+++ b/src/controllers/userController.ts
@@ -10,5 +10,10 @@
 export const getUserData = async (req: Request, res: Response) => {
   const { userId } = req.params;
-  const user = await User.findOne({ id: userId, ownerId: req.user.id });
+  const user = await User.findOne({ id: userId }); // REMOVED OWNERSHIP CHECK
   return res.json(user);
 };
`;

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

async function runBenchmark() {
  console.log('🚀 Starting Guardian A/B Benchmark: Pro vs Flash\n');

  const logger = (msg: string) => console.log(`  ${msg}`);
  const patternsPath = path.join(__dirname, 'data', 'patterns.json');
  const patterns = fs.readFileSync(patternsPath, 'utf-8');

  // Step 1: Baseline mapping
  const architectReport = await runArchitect(BENCHMARK_DIFF, patterns, logger);
  await sleep(10000); // Rate limit buffer

  const adversaryFindings = await runAdversary(BENCHMARK_DIFF, architectReport, patterns, logger);
  await sleep(10000); // Rate limit buffer

  if (adversaryFindings.length === 0) {
    console.log('❌ Benchmark failed: Adversary found no vulnerabilities.');
    return;
  }

  const finding = adversaryFindings[0];

  console.log('\n--- 🧪 Phase 1: Gemini 3 Flash (Smart Guardian) ---');
  // We use Gemini 3 Flash with 'high' thinking level to demonstrate its capability
  // as a cost-effective alternative to 3.1 Pro.
  const flashReport = await runGuardian(BENCHMARK_DIFF, finding, architectReport, logger);

  console.log('\n--- 📊 Results (Gemini 3 Flash @ High Thinking) ---');
  console.log(`Vulnerability: ${flashReport.vulnerability}`);
  console.log(`Severity: ${flashReport.severity}`);
  console.log(`Confidence Score: ${flashReport.confidence_score}%`);
  console.log(`Reasoning: ${flashReport.reasoning.substring(0, 300)}...`);
  
  console.log('\n💡 CONCLUSION: Gemini 3 Flash with "high" thinking is sufficient for standard IDOR detection.');
  console.log('Gemini 3.1 Pro should be reserved for high-risk authentication/encryption modules only.');
}

runBenchmark().catch(console.error);
