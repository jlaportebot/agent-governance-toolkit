// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Diagnostics;
using System.Text.Json;
using System.Threading.Tasks;

namespace AgentGovernance.EventSink;

/// <summary>
/// Reference <see cref="IGovernanceEventSink"/> that emits governance events via
/// <see cref="ActivitySource"/> — the built-in .NET distributed tracing API that
/// any OTLP-compatible backend can collect without additional NuGet packages.
/// </summary>
/// <remarks>
/// <para>
/// OTLP-compatible backends include: Microsoft Defender for Cloud, Microsoft Sentinel,
/// Splunk, Datadog, Honeycomb, Dynatrace, Grafana Tempo, and any OpenTelemetry Collector.
/// </para>
/// <para>
/// <b>Wiring with OpenTelemetry SDK:</b>
/// <code>
/// using var tracerProvider = Sdk.CreateTracerProviderBuilder()
///     .AddSource(OtlpEventSink.ActivitySourceName)
///     .AddOtlpExporter()
///     .Build();
///
/// var sink = new OtlpEventSink();
/// </code>
/// </para>
/// </remarks>
public sealed class OtlpEventSink : IGovernanceEventSink
{
    /// <summary>
    /// The <see cref="ActivitySource"/> name used for all governance events.
    /// Register this with your OTEL TracerProvider to collect events.
    /// </summary>
    public const string ActivitySourceName = "AgentGovernance.EventSink";

    private static readonly ActivitySource _source =
        new(ActivitySourceName, "1.0.0");

    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = false,
    };

    /// <summary>
    /// Emit a governance event as an <see cref="Activity"/> event on an OTEL span.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each call creates a short-lived span under <see cref="ActivitySourceName"/>
    /// and attaches the event payload as span attributes.  When no OTEL exporter
    /// is listening (i.e. no <see cref="ActivityListener"/> is registered for this
    /// source), the call is a safe no-op.
    /// </para>
    /// </remarks>
    public ValueTask EmitAsync(SignedGovernanceEvent governanceEvent)
    {
        ArgumentNullException.ThrowIfNull(governanceEvent);

        using var activity = _source.StartActivity(
            governanceEvent.Type,
            ActivityKind.Internal);

        if (activity is not null)
        {
            activity.SetTag("agt.governance.event.id", governanceEvent.Id);
            activity.SetTag("agt.governance.event.type", governanceEvent.Type);
            activity.SetTag("agt.governance.event.source", governanceEvent.Source);
            activity.SetTag("agt.governance.event.subject", governanceEvent.Subject);
            activity.SetTag("agt.governance.event.signed", !string.IsNullOrEmpty(governanceEvent.Signature));
            activity.SetTag("agt.governance.event.specversion", governanceEvent.SpecVersion);
            activity.SetTag("agt.governance.event.time", governanceEvent.Time.ToString("O"));
            activity.SetTag("agt.governance.event.datacontenttype", governanceEvent.DataContentType);

            // Attach the full CloudEvents JSON payload as a span event for backends
            // that surface span events (Jaeger, Zipkin, Datadog APM, etc.).
            var dataJson = JsonSerializer.Serialize(governanceEvent.Data, _jsonOptions);
            var tags = new ActivityTagsCollection
            {
                { "event.domain", "agent_governance" },
                { "event.body", dataJson },
            };
            activity.AddEvent(new ActivityEvent("governance_event", tags: tags));
        }

        return ValueTask.CompletedTask;
    }
}
