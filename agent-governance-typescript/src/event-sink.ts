// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Pluggable GovernanceEventSink — provider interface (SPI) for governance event routing.
 *
 * Defines the sink interface and two reference implementations:
 *
 * - {@link StdoutEventSink} — writes JSON to stdout; suitable for development and CI.
 * - {@link OtlpEventSink} — POSTs to an OTLP HTTP endpoint; compatible with Defender for
 *   Cloud, Microsoft Sentinel, Splunk, Datadog, and any OTLP-capable backend.
 *
 * Architecture
 * ------------
 * AGT emits structured, signed governance events; the *sink* routes them to external
 * observability and enforcement backends. This project does not implement OS-level
 * enforcement — that is the responsibility of the backend (Defender, Falco, Tetragon, etc.).
 *
 * Event Categories (aligned with CloudEvents + OTEL semantic conventions):
 * - `policy.decision`    — policy allow/deny/warn/require-approval outcome
 * - `policy.breach`      — policy violation detected
 * - `identity.assertion` — agent identity claim or verification result
 * - `tool.invocation`    — tool call intercepted before execution
 * - `sandbox.event`      — sandbox lifecycle event (create, execute, destroy)
 * - `audit.chain`        — hash-chain audit entry emitted
 */

import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import * as https from 'https';
import * as http from 'http';
import { randomUUID } from 'crypto';

// ---------------------------------------------------------------------------
// Event categories
// ---------------------------------------------------------------------------

/** Categories of governance events emitted through the {@link GovernanceEventSink} SPI. */
export enum GovernanceEventCategory {
  PolicyDecision = 'policy.decision',
  PolicyBreach = 'policy.breach',
  IdentityAssertion = 'identity.assertion',
  ToolInvocation = 'tool.invocation',
  SandboxEvent = 'sandbox.event',
  AuditChain = 'audit.chain',
}

/** Returns the full CloudEvents `type` string for a {@link GovernanceEventCategory}. */
export function cloudEventType(category: GovernanceEventCategory): string {
  return `ai.agentmesh.${category}`;
}

// ---------------------------------------------------------------------------
// Canonical signed event envelope
// ---------------------------------------------------------------------------

/**
 * CloudEvents 1.0 envelope with HMAC-SHA256 tamper-evidence signature.
 *
 * Fields follow the [CloudEvents specification](https://github.com/cloudevents/spec).
 * The `signature` extension field is an HMAC-SHA256 of the canonical form:
 * ```
 * "{type}\n{source}\n{time}\n{id}\n{dataJson}"
 * ```
 * When no signing key is supplied `signature` is left empty.
 */
export interface SignedGovernanceEvent {
  /** CloudEvents specification version. Always `"1.0"`. */
  readonly specversion: '1.0';
  /** Unique event identifier. */
  readonly id: string;
  /** CloudEvents type string, e.g. `"ai.agentmesh.policy.decision"`. */
  readonly type: string;
  /** Agent DID or service URI that produced the event. */
  readonly source: string;
  /** ISO 8601 UTC timestamp. */
  readonly time: string;
  /** Content type. Always `"application/json"`. */
  readonly datacontenttype: 'application/json';
  /** Tool name, resource path, or context-specific subject. */
  readonly subject: string;
  /** Event-specific payload. */
  readonly data: Record<string, unknown>;
  /** HMAC-SHA256 hex signature of the canonical form. Empty when unsigned. */
  readonly signature: string;
}

/**
 * Constructs and optionally signs a {@link SignedGovernanceEvent}.
 *
 * @param category   The governance event category.
 * @param source     Agent DID or service URI.
 * @param subject    Tool name, resource, or subject string.
 * @param data       Arbitrary event payload. Defaults to `{}`.
 * @param signingKey Raw bytes used as the HMAC-SHA256 signing key.
 *                   When `null`/`undefined`, the event is unsigned.
 */
export function buildGovernanceEvent(
  category: GovernanceEventCategory,
  source: string,
  subject = '',
  data: Record<string, unknown> = {},
  signingKey?: Uint8Array | null,
): SignedGovernanceEvent {
  const now = new Date().toISOString();
  const id = randomUUID();
  const type = cloudEventType(category);
  const dataJson = JSON.stringify(data);

  let signature = '';
  if (signingKey && signingKey.length > 0) {
    const canonical = `${type}\n${source}\n${now}\n${id}\n${dataJson}`;
    const mac = hmac(sha256, signingKey, new TextEncoder().encode(canonical));
    signature = bytesToHex(mac);
  }

  return {
    specversion: '1.0',
    id,
    type,
    source,
    time: now,
    datacontenttype: 'application/json',
    subject,
    data,
    signature,
  };
}

/**
 * Verifies the HMAC-SHA256 signature of a {@link SignedGovernanceEvent}.
 *
 * @returns `true` if the signature is valid; `false` if invalid or unsigned.
 */
export function verifyGovernanceEventSignature(
  event: SignedGovernanceEvent,
  signingKey: Uint8Array,
): boolean {
  if (!event.signature) return false;
  const dataJson = JSON.stringify(event.data);
  const canonical = `${event.type}\n${event.source}\n${event.time}\n${event.id}\n${dataJson}`;
  const mac = hmac(sha256, signingKey, new TextEncoder().encode(canonical));
  const expected = bytesToHex(mac);
  // Constant-time comparison
  if (expected.length !== event.signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ event.signature.charCodeAt(i);
  }
  return diff === 0;
}

// ---------------------------------------------------------------------------
// Sink interface
// ---------------------------------------------------------------------------

/**
 * Provider interface (SPI) for governance event routing.
 *
 * One async method — {@link GovernanceEventSink.emit} — takes a
 * {@link SignedGovernanceEvent} and forwards it to the configured backend.
 * Mirrors the `SandboxProvider` shape for consistency.
 *
 * Reference implementations:
 * - {@link StdoutEventSink} — JSON to stdout (dev/CI)
 * - {@link OtlpEventSink} — OTLP HTTP (Defender, Sentinel, Splunk, …)
 */
export interface GovernanceEventSink {
  /** Emit a governance event to the configured backend. */
  emit(event: SignedGovernanceEvent): Promise<void>;
}

// ---------------------------------------------------------------------------
// Reference sink: Stdout
// ---------------------------------------------------------------------------

/**
 * Reference {@link GovernanceEventSink} that writes governance events as JSON
 * lines to `process.stdout`.
 *
 * Suitable for development, CI pipelines, and container environments where
 * stdout is collected by a log aggregator (Fluentd, Vector, Logstash, etc.).
 */
export class StdoutEventSink implements GovernanceEventSink {
  async emit(event: SignedGovernanceEvent): Promise<void> {
    process.stdout.write(JSON.stringify(event) + '\n');
  }
}

// ---------------------------------------------------------------------------
// Reference sink: OTLP
// ---------------------------------------------------------------------------

/** Configuration for {@link OtlpEventSink}. */
export interface OtlpEventSinkOptions {
  /**
   * OTLP HTTP endpoint for log ingestion.
   * Defaults to `http://localhost:4318/v1/logs`.
   */
  endpoint?: string;
  /**
   * Additional HTTP headers (e.g. `{ 'Authorization': 'Bearer <token>' }`).
   */
  headers?: Record<string, string>;
  /**
   * Timeout in milliseconds for each HTTP request. Defaults to `5000`.
   */
  timeoutMs?: number;
}

/**
 * Reference {@link GovernanceEventSink} that POSTs governance events to an
 * OTLP HTTP `/v1/logs` endpoint.
 *
 * Compatible with Microsoft Defender for Cloud, Microsoft Sentinel, Splunk,
 * Datadog, Honeycomb, Dynatrace, Grafana Loki, New Relic, and any
 * OpenTelemetry Collector.
 *
 * When the endpoint is unreachable, {@link emit} resolves without throwing
 * (the error is logged via `console.error`). This ensures the governance
 * pipeline is never blocked by sink unavailability.
 *
 * @example
 * ```ts
 * const sink = new OtlpEventSink({
 *   endpoint: 'http://otel-collector:4318/v1/logs',
 *   headers: { Authorization: 'Bearer my-token' },
 * });
 * await sink.emit(event);
 * ```
 */
export class OtlpEventSink implements GovernanceEventSink {
  private readonly endpoint: string;
  private readonly headers: Record<string, string>;
  private readonly timeoutMs: number;

  constructor(options?: OtlpEventSinkOptions) {
    this.endpoint = options?.endpoint ?? 'http://localhost:4318/v1/logs';
    this.headers = options?.headers ?? {};
    this.timeoutMs = options?.timeoutMs ?? 5000;
  }

  async emit(event: SignedGovernanceEvent): Promise<void> {
    // Wrap as a minimal OTLP LogsData JSON payload.
    const body = JSON.stringify({
      resourceLogs: [
        {
          resource: {
            attributes: [
              { key: 'service.name', value: { stringValue: 'agent-governance-toolkit' } },
            ],
          },
          scopeLogs: [
            {
              scope: { name: 'agent_governance.event_sink' },
              logRecords: [
                {
                  timeUnixNano: String(BigInt(new Date(event.time).getTime()) * 1_000_000n),
                  severityNumber: 9, // INFO
                  severityText: 'INFO',
                  body: { stringValue: JSON.stringify(event) },
                  attributes: [
                    { key: 'event.domain', value: { stringValue: 'agent_governance' } },
                    { key: 'event.name', value: { stringValue: 'governance_event' } },
                    { key: 'agt.governance.event.type', value: { stringValue: event.type } },
                    { key: 'agt.governance.event.source', value: { stringValue: event.source } },
                    { key: 'agt.governance.event.subject', value: { stringValue: event.subject } },
                    { key: 'agt.governance.event.id', value: { stringValue: event.id } },
                    { key: 'agt.governance.event.signed', value: { boolValue: event.signature !== '' } },
                  ],
                },
              ],
            },
          ],
        },
      ],
    });

    await this._post(body);
  }

  private _post(body: string): Promise<void> {
    return new Promise((resolve) => {
      const url = new URL(this.endpoint);
      const isHttps = url.protocol === 'https:';
      const lib = isHttps ? https : http;

      const req = lib.request(
        {
          hostname: url.hostname,
          port: url.port || (isHttps ? 443 : 80),
          path: url.pathname,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body),
            ...this.headers,
          },
        },
        (res) => {
          // Drain response to free the socket.
          res.resume();
          resolve();
        },
      );

      req.setTimeout(this.timeoutMs, () => {
        req.destroy();
        resolve();
      });

      req.on('error', () => resolve());
      req.write(body);
      req.end();
    });
  }
}
