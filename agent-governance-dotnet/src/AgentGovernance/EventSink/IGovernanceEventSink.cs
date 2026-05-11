// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace AgentGovernance.EventSink;

/// <summary>
/// Categories of governance events emitted through the <see cref="IGovernanceEventSink"/> SPI.
/// Values follow the <c>ai.agentmesh.&lt;category&gt;</c> CloudEvents type convention.
/// </summary>
public enum GovernanceEventCategory
{
    /// <summary>A policy allow/deny/warn/require-approval outcome was produced.</summary>
    PolicyDecision,

    /// <summary>A policy violation (breach) was detected.</summary>
    PolicyBreach,

    /// <summary>An agent identity claim or verification result was produced.</summary>
    IdentityAssertion,

    /// <summary>A tool call was intercepted before execution.</summary>
    ToolInvocation,

    /// <summary>A sandbox lifecycle event occurred (create, execute, destroy).</summary>
    SandboxEvent,

    /// <summary>A hash-chain audit entry was emitted.</summary>
    AuditChain,
}

/// <summary>
/// CloudEvents 1.0 envelope with HMAC-SHA256 tamper-evidence signature.
/// </summary>
/// <remarks>
/// <para>
/// Fields follow the <see href="https://github.com/cloudevents/spec">CloudEvents specification</see>.
/// The <see cref="Signature"/> extension field is an HMAC-SHA256 of the canonical form:
/// <code>
/// "{Type}\n{Source}\n{Time:O}\n{Id}\n{DataJson}"
/// </code>
/// When no signing key is supplied, <see cref="Signature"/> is left empty.
/// </para>
/// <para>
/// <b>Quick start:</b>
/// <code>
/// var evt = SignedGovernanceEvent.Build(
///     GovernanceEventCategory.PolicyDecision,
///     source: "did:agentmesh:agent-1",
///     subject: "tool:file_write",
///     data: new() { ["decision"] = "deny", ["reason"] = "path blocked" });
/// </code>
/// </para>
/// </remarks>
public sealed class SignedGovernanceEvent
{
    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = false,
    };

    /// <summary>CloudEvents specification version. Always <c>"1.0"</c>.</summary>
    public string SpecVersion { get; init; } = "1.0";

    /// <summary>Unique event identifier (format: <c>evt-{guid}</c>).</summary>
    public string Id { get; init; } = $"evt-{Guid.NewGuid():N}";

    /// <summary>
    /// CloudEvents type string, e.g. <c>"ai.agentmesh.policy.decision"</c>.
    /// </summary>
    public string Type { get; init; } = string.Empty;

    /// <summary>Agent DID or service URI that produced the event.</summary>
    public string Source { get; init; } = string.Empty;

    /// <summary>UTC timestamp of when the event occurred.</summary>
    public DateTimeOffset Time { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Content type of <see cref="Data"/>. Always <c>"application/json"</c>.</summary>
    public string DataContentType { get; init; } = "application/json";

    /// <summary>
    /// Tool name, resource path, or other context-specific subject string.
    /// </summary>
    public string Subject { get; init; } = string.Empty;

    /// <summary>Event-specific payload.</summary>
    public Dictionary<string, object> Data { get; init; } = new();

    /// <summary>
    /// HMAC-SHA256 hex signature of the canonical form. Empty when unsigned.
    /// </summary>
    public string Signature { get; init; } = string.Empty;

    /// <summary>
    /// Returns the canonical CloudEvents type string for a <see cref="GovernanceEventCategory"/>.
    /// </summary>
    public static string CloudEventType(GovernanceEventCategory category) => category switch
    {
        GovernanceEventCategory.PolicyDecision => "ai.agentmesh.policy.decision",
        GovernanceEventCategory.PolicyBreach => "ai.agentmesh.policy.breach",
        GovernanceEventCategory.IdentityAssertion => "ai.agentmesh.identity.assertion",
        GovernanceEventCategory.ToolInvocation => "ai.agentmesh.tool.invocation",
        GovernanceEventCategory.SandboxEvent => "ai.agentmesh.sandbox.event",
        GovernanceEventCategory.AuditChain => "ai.agentmesh.audit.chain",
        _ => $"ai.agentmesh.{category.ToString().ToLowerInvariant()}",
    };

    /// <summary>
    /// Constructs and optionally signs a <see cref="SignedGovernanceEvent"/>.
    /// </summary>
    /// <param name="category">The governance event category.</param>
    /// <param name="source">Agent DID or service URI.</param>
    /// <param name="subject">Tool name, resource, or subject string.</param>
    /// <param name="data">Arbitrary event payload. Defaults to an empty dictionary.</param>
    /// <param name="signingKey">
    /// Raw bytes used as the HMAC-SHA256 signing key.
    /// When <c>null</c> or empty, the event is unsigned (<see cref="Signature"/> is empty).
    /// </param>
    /// <returns>A fully constructed <see cref="SignedGovernanceEvent"/>.</returns>
    public static SignedGovernanceEvent Build(
        GovernanceEventCategory category,
        string source,
        string subject = "",
        Dictionary<string, object>? data = null,
        byte[]? signingKey = null)
    {
        var now = DateTimeOffset.UtcNow;
        var id = $"evt-{Guid.NewGuid():N}";
        var type = CloudEventType(category);
        var payload = data ?? new Dictionary<string, object>();
        var dataJson = JsonSerializer.Serialize(payload, _jsonOptions);

        var sig = string.Empty;
        if (signingKey is { Length: > 0 })
        {
            var canonical = $"{type}\n{source}\n{now:O}\n{id}\n{dataJson}";
            using var hmac = new HMACSHA256(signingKey);
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical));
            sig = Convert.ToHexString(hash).ToLowerInvariant();
        }

        return new SignedGovernanceEvent
        {
            Id = id,
            Type = type,
            Source = source,
            Time = now,
            Subject = subject,
            Data = payload,
            Signature = sig,
        };
    }

    /// <summary>
    /// Verifies the HMAC-SHA256 <see cref="Signature"/> against <paramref name="signingKey"/>.
    /// </summary>
    /// <param name="signingKey">The key used to verify the signature.</param>
    /// <returns>
    /// <c>true</c> if the signature is valid; <c>false</c> if invalid or the event is unsigned.
    /// </returns>
    public bool VerifySignature(byte[] signingKey)
    {
        if (string.IsNullOrEmpty(Signature)) return false;

        var dataJson = JsonSerializer.Serialize(Data, _jsonOptions);
        var canonical = $"{Type}\n{Source}\n{Time:O}\n{Id}\n{dataJson}";
        using var hmac = new HMACSHA256(signingKey);
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical));
        var expected = Convert.ToHexString(hash).ToLowerInvariant();
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(Signature),
            Encoding.ASCII.GetBytes(expected));
    }

    /// <inheritdoc />
    public override string ToString() =>
        $"[{Time:O}] {Type} source={Source} subject={Subject} signed={!string.IsNullOrEmpty(Signature)}";
}

/// <summary>
/// Provider interface (SPI) for governance event routing.
/// </summary>
/// <remarks>
/// <para>
/// One async method — <see cref="EmitAsync"/> — takes a <see cref="SignedGovernanceEvent"/>
/// and forwards it to the configured backend. Mirrors the
/// <see cref="AgentGovernance.Sandbox.ISandboxProvider"/> shape for consistency.
/// </para>
/// <para>
/// Reference implementations:
/// <list type="bullet">
///   <item><see cref="StdoutEventSink"/> — JSON to stdout (dev/CI)</item>
///   <item><see cref="OtlpEventSink"/> — OTLP ActivitySource (Defender, Sentinel, Splunk, …)</item>
/// </list>
/// </para>
/// <para>
/// <b>Quick start:</b>
/// <code>
/// IGovernanceEventSink sink = new StdoutEventSink();
/// var evt = SignedGovernanceEvent.Build(
///     GovernanceEventCategory.PolicyDecision,
///     source: "did:agentmesh:agent-1",
///     subject: "tool:file_write",
///     data: new() { ["decision"] = "deny" });
/// await sink.EmitAsync(evt);
/// </code>
/// </para>
/// </remarks>
public interface IGovernanceEventSink
{
    /// <summary>
    /// Emit a governance event to the configured backend.
    /// </summary>
    /// <param name="governanceEvent">The signed event to forward.</param>
    ValueTask EmitAsync(SignedGovernanceEvent governanceEvent);
}
