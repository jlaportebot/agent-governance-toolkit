// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Text.Json;
using System.Threading.Tasks;

namespace AgentGovernance.EventSink;

/// <summary>
/// Reference <see cref="IGovernanceEventSink"/> that writes governance events as
/// JSON lines to <see cref="Console.Out"/>.
/// </summary>
/// <remarks>
/// <para>
/// Suitable for development, CI pipelines, and container environments where stdout
/// is collected by a log aggregator (Fluentd, Vector, Logstash, AWS CloudWatch Logs, etc.).
/// </para>
/// <para>
/// <b>Example output</b> (one JSON line per event):
/// <code>
/// {"specVersion":"1.0","id":"evt-abc123","type":"ai.agentmesh.policy.decision","source":"did:agentmesh:agent-1",...}
/// </code>
/// </para>
/// </remarks>
public sealed class StdoutEventSink : IGovernanceEventSink
{
    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    /// <summary>
    /// Write the event as a single JSON line to <see cref="Console.Out"/>.
    /// </summary>
    public ValueTask EmitAsync(SignedGovernanceEvent governanceEvent)
    {
        ArgumentNullException.ThrowIfNull(governanceEvent);

        var json = JsonSerializer.Serialize(new
        {
            specVersion = governanceEvent.SpecVersion,
            id = governanceEvent.Id,
            type = governanceEvent.Type,
            source = governanceEvent.Source,
            time = governanceEvent.Time.ToString("O"),
            dataContentType = governanceEvent.DataContentType,
            subject = governanceEvent.Subject,
            data = governanceEvent.Data,
            signature = governanceEvent.Signature,
        }, _jsonOptions);

        Console.WriteLine(json);

        return ValueTask.CompletedTask;
    }
}
