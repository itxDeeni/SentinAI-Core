import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runOrchestrator } from '../analyzer';
import * as ai from 'ai';

// Mock the AI SDK generateText function
vi.mock('ai', () => ({
  generateText: vi.fn(),
}));

describe('SentinAI Core: Analyzer Hybrid Routing', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GEMINI_API_KEY = 'test-key';
    process.env.NODE_ENV = 'development';
  });

  it('should route Architect to Flash Lite (8b) and Adversary to Full Flash', async () => {
    const mockGenerateText = vi.mocked(ai.generateText);

    // Mock sequence of responses for Architect, Adversary, and Guardian
    mockGenerateText
      .mockResolvedValueOnce({ text: JSON.stringify({ endpoints: [], auth_middleware: [], vulnerability_surface: 'none', rbac_mapping: 'none' }) } as any) // Architect
      .mockResolvedValueOnce({ text: '[]' } as any); // Adversary (no findings)

    const logger = vi.fn();
    const diff = 'diff --git a/src/index.ts b/src/index.ts...';

    await runOrchestrator(diff, logger);

    // Verify calls
    expect(mockGenerateText).toHaveBeenCalledTimes(2);

    // Check Architect call (first call)
    const architectCall = mockGenerateText.mock.calls[0][0] as any;
    // In dev, lite maps to gemini-1.5-flash-8b
    expect(architectCall.model.modelId).toContain('8b');

    // Check Adversary call (second call)
    const adversaryCall = mockGenerateText.mock.calls[1][0] as any;
    // In dev, pro maps to gemini-1.5-flash
    expect(adversaryCall.model.modelId).toBe('gemini-1.5-flash');
  });

  it('should handle malformed JSON from Architect gracefully', async () => {
    const mockGenerateText = vi.mocked(ai.generateText);
    
    // Architect returns garbage, Adversary returns no findings
    mockGenerateText
      .mockResolvedValueOnce({ text: 'Not JSON at all' } as any)
      .mockResolvedValueOnce({ text: '[]' } as any);

    const logger = vi.fn();
    const results = await runOrchestrator('some diff', logger);

    expect(results).toEqual([]);
    expect(logger).toHaveBeenCalledWith(expect.stringContaining('Access control map complete'));
  });
});
