// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import {
  GovernanceEventCategory,
  StdoutEventSink,
  OtlpEventSink,
  buildGovernanceEvent,
  verifyGovernanceEventSignature,
  cloudEventType,
} from '../src/event-sink';
import type { SignedGovernanceEvent, GovernanceEventSink } from '../src/event-sink';

// ---------------------------------------------------------------------------
// GovernanceEventCategory
// ---------------------------------------------------------------------------

describe('GovernanceEventCategory', () => {
  it('has six categories', () => {
    const cats = Object.values(GovernanceEventCategory);
    expect(cats).toHaveLength(6);
  });

  it('cloudEventType returns correct prefix', () => {
    expect(cloudEventType(GovernanceEventCategory.PolicyDecision)).toBe(
      'ai.agentmesh.policy.decision',
    );
    expect(cloudEventType(GovernanceEventCategory.PolicyBreach)).toBe(
      'ai.agentmesh.policy.breach',
    );
    expect(cloudEventType(GovernanceEventCategory.IdentityAssertion)).toBe(
      'ai.agentmesh.identity.assertion',
    );
    expect(cloudEventType(GovernanceEventCategory.ToolInvocation)).toBe(
      'ai.agentmesh.tool.invocation',
    );
    expect(cloudEventType(GovernanceEventCategory.SandboxEvent)).toBe(
      'ai.agentmesh.sandbox.event',
    );
    expect(cloudEventType(GovernanceEventCategory.AuditChain)).toBe(
      'ai.agentmesh.audit.chain',
    );
  });

  it('all categories have distinct cloud event types', () => {
    const types = Object.values(GovernanceEventCategory).map(cloudEventType);
    const unique = new Set(types);
    expect(unique.size).toBe(types.length);
  });
});

// ---------------------------------------------------------------------------
// buildGovernanceEvent
// ---------------------------------------------------------------------------

describe('buildGovernanceEvent', () => {
  it('sets specversion to 1.0', () => {
    const evt = buildGovernanceEvent(
      GovernanceEventCategory.PolicyDecision,
      'did:agentmesh:agent-1',
    );
    expect(evt.specversion).toBe('1.0');
  });

  it('sets correct type from category', () => {
    const evt = buildGovernanceEvent(
      GovernanceEventCategory.PolicyBreach,
      'did:agentmesh:agent-1',
    );
    expect(evt.type).toBe('ai.agentmesh.policy.breach');
  });

  it('sets source correctly', () => {
    const evt = buildGovernanceEvent(
      GovernanceEventCategory.ToolInvocation,
      'did:agentmesh:agent-42',
    );
    expect(evt.source).toBe('did:agentmesh:agent-42');
  });

  it('sets subject correctly', () => {
    const evt = buildGovernanceEvent(
      GovernanceEventCategory.ToolInvocation,
      'did:agentmesh:a',
      'tool:file_write',
    );
    expect(evt.subject).toBe('tool:file_write');
  });

  it('sets data correctly', () => {
    const data = { decision: 'deny', reason: 'blocked' };
    const evt = buildGovernanceEvent(
      GovernanceEventCategory.PolicyDecision,
      'did:agentmesh:a',
      '',
      data,
    );
    expect(evt.data).toEqual(data);
  });

  it('has empty signature when no key provided', () => {
    const evt = buildGovernanceEvent(
      GovernanceEventCategory.PolicyDecision,
      'did:agentmesh:a',
    );
    expect(evt.signature).toBe('');
  });

  it('has 64-char hex signature when key provided', () => {
    const key = new TextEncoder().encode('test-signing-key-for-hmac-sha256');
    const evt = buildGovernanceEvent(
      GovernanceEventCategory.PolicyDecision,
      'did:agentmesh:a',
      '',
      {},
      key,
    );
    expect(evt.signature).toHaveLength(64);
    expect(/^[0-9a-f]+$/.test(evt.signature)).toBe(true);
  });

  it('has datacontenttype of application/json', () => {
    const evt = buildGovernanceEvent(
      GovernanceEventCategory.PolicyDecision,
      'did:agentmesh:a',
    );
    expect(evt.datacontenttype).toBe('application/json');
  });

  it('generates unique ids', () => {
    const evt1 = buildGovernanceEvent(GovernanceEventCategory.PolicyDecision, 'did:agentmesh:a');
    const evt2 = buildGovernanceEvent(GovernanceEventCategory.PolicyDecision, 'did:agentmesh:a');
    expect(evt1.id).not.toBe(evt2.id);
  });

  it('time is a valid ISO 8601 string', () => {
    const evt = buildGovernanceEvent(GovernanceEventCategory.AuditChain, 'did:agentmesh:a');
    expect(() => new Date(evt.time)).not.toThrow();
    expect(new Date(evt.time).toISOString()).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// verifyGovernanceEventSignature
// ---------------------------------------------------------------------------

describe('verifyGovernanceEventSignature', () => {
  it('returns true for valid signature', () => {
    const key = new TextEncoder().encode('test-key-1234567890123456789012');
    const evt = buildGovernanceEvent(
      GovernanceEventCategory.ToolInvocation,
      'did:agentmesh:agent-1',
      'tool:web_search',
      { query: 'test' },
      key,
    );
    expect(verifyGovernanceEventSignature(evt, key)).toBe(true);
  });

  it('returns false for wrong key', () => {
    const key = new TextEncoder().encode('correct-key-1234567890123456789');
    const evt = buildGovernanceEvent(
      GovernanceEventCategory.ToolInvocation,
      'did:agentmesh:agent-1',
      '',
      {},
      key,
    );
    const wrongKey = new TextEncoder().encode('wrong-key-xxxxxxxxxxxxxxxxxxxxxxx');
    expect(verifyGovernanceEventSignature(evt, wrongKey)).toBe(false);
  });

  it('returns false for unsigned event', () => {
    const evt = buildGovernanceEvent(GovernanceEventCategory.AuditChain, 'did:agentmesh:a');
    expect(verifyGovernanceEventSignature(evt, new TextEncoder().encode('any-key'))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// StdoutEventSink
// ---------------------------------------------------------------------------

describe('StdoutEventSink', () => {
  it('emits without throwing', async () => {
    const sink = new StdoutEventSink();
    const evt = buildGovernanceEvent(
      GovernanceEventCategory.PolicyDecision,
      'did:agentmesh:agent-1',
      'tool:file_write',
      { decision: 'deny' },
    );
    await expect(sink.emit(evt)).resolves.toBeUndefined();
  });

  it('satisfies GovernanceEventSink interface', () => {
    const sink: GovernanceEventSink = new StdoutEventSink();
    expect(typeof sink.emit).toBe('function');
  });

  it('writes JSON to stdout', async () => {
    const written: string[] = [];
    const original = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk: any, ...args: any[]): any => {
      written.push(String(chunk));
      return true;
    };
    try {
      const sink = new StdoutEventSink();
      const evt = buildGovernanceEvent(
        GovernanceEventCategory.PolicyDecision,
        'did:agentmesh:a',
      );
      await sink.emit(evt);
      const output = written.join('');
      const parsed = JSON.parse(output.trim());
      expect(parsed.type).toBe('ai.agentmesh.policy.decision');
    } finally {
      process.stdout.write = original;
    }
  });
});

// ---------------------------------------------------------------------------
// OtlpEventSink
// ---------------------------------------------------------------------------

describe('OtlpEventSink', () => {
  it('resolves without throwing when endpoint is unreachable', async () => {
    // Port 1 is typically not listening
    const sink = new OtlpEventSink({
      endpoint: 'http://localhost:1/v1/logs',
      timeoutMs: 100,
    });
    const evt = buildGovernanceEvent(
      GovernanceEventCategory.PolicyDecision,
      'did:agentmesh:agent-1',
    );
    // Should resolve (error swallowed internally)
    await expect(sink.emit(evt)).resolves.toBeUndefined();
  });

  it('satisfies GovernanceEventSink interface', () => {
    const sink: GovernanceEventSink = new OtlpEventSink();
    expect(typeof sink.emit).toBe('function');
  });

  it('uses default endpoint when not specified', () => {
    const sink = new OtlpEventSink();
    // Default endpoint is http://localhost:4318/v1/logs
    // (We cannot easily inspect private fields, just ensure construction works)
    expect(sink).toBeInstanceOf(OtlpEventSink);
  });
});

// ---------------------------------------------------------------------------
// Type compatibility
// ---------------------------------------------------------------------------

describe('type compatibility', () => {
  it('SignedGovernanceEvent is structurally compatible with the interface', () => {
    const evt: SignedGovernanceEvent = buildGovernanceEvent(
      GovernanceEventCategory.PolicyDecision,
      'did:agentmesh:a',
    );
    expect(evt.specversion).toBe('1.0');
    expect(evt.datacontenttype).toBe('application/json');
  });
});
