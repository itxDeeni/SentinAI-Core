import type { GuardianReport } from './analyzer';

/**
 * Converts a list of SentinAI findings into v2.1.0 SARIF format.
 * This allows native integration into the GitHub Security tab and other SAST ingestors.
 */
export function convertToSarif(findings: GuardianReport[], repoName: string = 'repository'): object {
  const rules = new Map<string, any>();
  const results: any[] = [];

  for (const finding of findings) {
    // Determine SARIF severity level based on SentinAI severity
    let level = 'warning';
    if (finding.severity === 'CRITICAL' || finding.severity === 'HIGH') level = 'error';
    if (finding.severity === 'LOW') level = 'note';

    // Build unique rule ID based on OWASP category and finding type
    const ruleId = (finding.owasp_category.split(' ')[0] || 'VULN').replace(/[^a-zA-Z0-9-]/g, '') + '-' + finding.severity;

    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        shortDescription: { text: finding.owasp_category },
        fullDescription: { text: `SentinAI identified a ${finding.severity} severity vulnerability in this category.` },
        properties: {
          category: 'security',
          precision: 'high',
          tags: ['security', finding.owasp_category],
        }
      });
    }

    results.push({
      ruleId,
      level,
      message: {
        text: `Vulnerability: ${finding.vulnerability}\nConfidence: ${finding.confidence_score}%\nEndpoint: ${finding.affected_endpoint}\n\nReasoning: ${finding.reasoning}\n\nSuggested Fix: \n${finding.suggested_fix}`
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: 'sentinai-analysis-result.json', // Placeholder, as LLM line-mapping is inexact
              uriBaseId: '%SRCROOT%'
            },
            region: {
              startLine: 1
            }
          }
        }
      ]
    });
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'SentinAI Autonomous Auditor',
            informationUri: 'https://getsentinai.com',
            version: '1.0.0',
            rules: Array.from(rules.values())
          }
        },
        results
      }
    ]
  };
}
