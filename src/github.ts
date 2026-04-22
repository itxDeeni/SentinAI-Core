import { Octokit } from '@octokit/rest';

/**
 * Fetch the unified diff for a GitHub PR.
 * This is a core utility used by the SentinAI CLI and SaaS engine.
 * 
 * @param owner - Repository owner
 * @param repo - Repository name
 * @param prNumber - Pull request number
 * @param octokitOverride - Optional authenticated Octokit instance (defaults to GITHUB_TOKEN)
 * @returns The raw unified diff string
 */
export async function fetchPRDiff(
  owner: string,
  repo: string,
  prNumber: number,
  octokitOverride?: Octokit
): Promise<string> {
  // Fall back to a PAT-based client if no override is provided
  const client = octokitOverride ?? new Octokit({ auth: process.env.GITHUB_TOKEN });
  
  const response = await client.pulls.get({
    owner,
    repo,
    pull_number: prNumber,
    mediaType: { format: 'diff' },
  });
  
  return response.data as unknown as string;
}
