// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Text;
using AgentGovernance.Audit;
using AgentGovernance.EventSink;
using Xunit;

namespace AgentGovernance.Tests;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// <summary>
/// In-memory <see cref="IGovernanceEventSink"/> that captures emitted events.
/// </summary>
internal sealed class CaptureSink : IGovernanceEventSink
{
    public ConcurrentBag<SignedGovernanceEvent> Events { get; } = new();

    public ValueTask EmitAsync(SignedGovernanceEvent governanceEvent)
    {
        Events.Add(governanceEvent);
        return ValueTask.CompletedTask;
    }
}

// ---------------------------------------------------------------------------
// SignedGovernanceEvent tests
// ---------------------------------------------------------------------------

public class GovernanceEventSinkTests
{
    [Fact]
    public void Build_SetsSpecVersion_To_1_0()
    {
        var evt = SignedGovernanceEvent.Build(
            GovernanceEventCategory.PolicyDecision,
            source: "did:agentmesh:agent-1");

        Assert.Equal("1.0", evt.SpecVersion);
    }

    [Fact]
    public void Build_SetsType_MatchingCategory()
    {
        var evt = SignedGovernanceEvent.Build(
            GovernanceEventCategory.PolicyBreach,
            source: "did:agentmesh:agent-1");

        Assert.Equal("ai.agentmesh.policy.breach", evt.Type);
    }

    [Theory]
    [InlineData(GovernanceEventCategory.PolicyDecision, "ai.agentmesh.policy.decision")]
    [InlineData(GovernanceEventCategory.PolicyBreach, "ai.agentmesh.policy.breach")]
    [InlineData(GovernanceEventCategory.IdentityAssertion, "ai.agentmesh.identity.assertion")]
    [InlineData(GovernanceEventCategory.ToolInvocation, "ai.agentmesh.tool.invocation")]
    [InlineData(GovernanceEventCategory.SandboxEvent, "ai.agentmesh.sandbox.event")]
    [InlineData(GovernanceEventCategory.AuditChain, "ai.agentmesh.audit.chain")]
    public void CloudEventType_ReturnsCorrectString(GovernanceEventCategory cat, string expected)
    {
        Assert.Equal(expected, SignedGovernanceEvent.CloudEventType(cat));
    }

    [Fact]
    public void Build_SetsSource()
    {
        var evt = SignedGovernanceEvent.Build(
            GovernanceEventCategory.ToolInvocation,
            source: "did:agentmesh:agent-42");

        Assert.Equal("did:agentmesh:agent-42", evt.Source);
    }

    [Fact]
    public void Build_SetsSubject()
    {
        var evt = SignedGovernanceEvent.Build(
            GovernanceEventCategory.ToolInvocation,
            source: "did:agentmesh:a",
            subject: "tool:file_write");

        Assert.Equal("tool:file_write", evt.Subject);
    }

    [Fact]
    public void Build_SetsData()
    {
        var data = new Dictionary<string, object> { ["decision"] = "deny", ["reason"] = "blocked" };
        var evt = SignedGovernanceEvent.Build(
            GovernanceEventCategory.PolicyDecision,
            source: "did:agentmesh:a",
            data: data);

        Assert.Equal("deny", evt.Data["decision"]);
        Assert.Equal("blocked", evt.Data["reason"]);
    }

    [Fact]
    public void Build_WithNoSigningKey_HasEmptySignature()
    {
        var evt = SignedGovernanceEvent.Build(
            GovernanceEventCategory.PolicyDecision,
            source: "did:agentmesh:a");

        Assert.Empty(evt.Signature);
    }

    [Fact]
    public void Build_WithSigningKey_HasNonEmptySignature()
    {
        var key = Encoding.UTF8.GetBytes("test-key-for-hmac-sha256-32bytes");
        var evt = SignedGovernanceEvent.Build(
            GovernanceEventCategory.PolicyDecision,
            source: "did:agentmesh:a",
            signingKey: key);

        Assert.NotEmpty(evt.Signature);
        Assert.Equal(64, evt.Signature.Length); // 32 bytes HMAC = 64 hex chars
    }

    [Fact]
    public void VerifySignature_WithCorrectKey_ReturnsTrue()
    {
        var key = Encoding.UTF8.GetBytes("correct-key-12345678901234567890");
        var evt = SignedGovernanceEvent.Build(
            GovernanceEventCategory.ToolInvocation,
            source: "did:agentmesh:agent-1",
            subject: "tool:web_search",
            data: new() { ["query"] = "test" },
            signingKey: key);

        Assert.True(evt.VerifySignature(key));
    }

    [Fact]
    public void VerifySignature_WithWrongKey_ReturnsFalse()
    {
        var key = Encoding.UTF8.GetBytes("correct-key-12345678901234567890");
        var evt = SignedGovernanceEvent.Build(
            GovernanceEventCategory.ToolInvocation,
            source: "did:agentmesh:agent-1",
            signingKey: key);

        var wrongKey = Encoding.UTF8.GetBytes("wrong-key-xxxxxxxxxxxxxxxxxxxxxxx");
        Assert.False(evt.VerifySignature(wrongKey));
    }

    [Fact]
    public void VerifySignature_Unsigned_ReturnsFalse()
    {
        var evt = SignedGovernanceEvent.Build(
            GovernanceEventCategory.AuditChain,
            source: "did:agentmesh:a");

        Assert.False(evt.VerifySignature(Encoding.UTF8.GetBytes("any-key")));
    }

    [Fact]
    public void Build_SetDataContentType()
    {
        var evt = SignedGovernanceEvent.Build(
            GovernanceEventCategory.PolicyDecision,
            source: "did:agentmesh:a");

        Assert.Equal("application/json", evt.DataContentType);
    }

    [Fact]
    public void Build_DifferentCalls_HaveDifferentIds()
    {
        var evt1 = SignedGovernanceEvent.Build(GovernanceEventCategory.PolicyDecision, "did:agentmesh:a");
        var evt2 = SignedGovernanceEvent.Build(GovernanceEventCategory.PolicyDecision, "did:agentmesh:a");

        Assert.NotEqual(evt1.Id, evt2.Id);
    }

    [Fact]
    public void ToString_ContainsKeyInfo()
    {
        var evt = SignedGovernanceEvent.Build(
            GovernanceEventCategory.PolicyDecision,
            source: "did:agentmesh:a",
            subject: "tool:test");

        var str = evt.ToString();
        Assert.Contains("ai.agentmesh.policy.decision", str);
        Assert.Contains("did:agentmesh:a", str);
    }

    // ---------------------------------------------------------------------------
    // StdoutEventSink
    // ---------------------------------------------------------------------------

    [Fact]
    public async Task StdoutEventSink_EmitsWithoutException()
    {
        var sink = new StdoutEventSink();
        var evt = SignedGovernanceEvent.Build(
            GovernanceEventCategory.PolicyDecision,
            source: "did:agentmesh:agent-1",
            subject: "tool:file_write",
            data: new() { ["decision"] = "deny" });

        // Should not throw
        await sink.EmitAsync(evt);
    }

    // ---------------------------------------------------------------------------
    // OtlpEventSink
    // ---------------------------------------------------------------------------

    [Fact]
    public async Task OtlpEventSink_EmitsWithoutException()
    {
        // OtlpEventSink uses ActivitySource which is a no-op without a listener.
        var sink = new OtlpEventSink();
        var evt = SignedGovernanceEvent.Build(
            GovernanceEventCategory.PolicyDecision,
            source: "did:agentmesh:agent-1");

        await sink.EmitAsync(evt);
    }

    [Fact]
    public void OtlpEventSink_ActivitySourceName_IsCorrect()
    {
        Assert.Equal("AgentGovernance.EventSink", OtlpEventSink.ActivitySourceName);
    }

    // ---------------------------------------------------------------------------
    // GovernanceKernel integration with EventSink
    // ---------------------------------------------------------------------------

    [Fact]
    public async Task GovernanceKernel_WithEventSink_ForwardsAuditEvents()
    {
        var capture = new CaptureSink();
        var kernel = new GovernanceKernel(new GovernanceOptions
        {
            EnableAudit = true,
            EventSink = capture,
        });

        // Trigger a policy check which emits an audit event
        kernel.EvaluateToolCall("did:agentmesh:agent-1", "file.read");

        // Allow time for async fire-and-forget
        await Task.Delay(50);

        Assert.True(capture.Events.Count >= 1, "Expected at least one event to be forwarded");
    }

    [Fact]
    public async Task GovernanceKernel_WithEventSink_EventHasCorrectSource()
    {
        var capture = new CaptureSink();
        var kernel = new GovernanceKernel(new GovernanceOptions
        {
            EnableAudit = true,
            EventSink = capture,
        });

        kernel.EvaluateToolCall("did:agentmesh:agent-42", "data.read");
        await Task.Delay(50);

        var evt = capture.Events.FirstOrDefault();
        Assert.NotNull(evt);
        Assert.Equal("did:agentmesh:agent-42", evt!.Source);
    }

    [Fact]
    public async Task GovernanceKernel_WithSigningKey_EventsAreSigned()
    {
        var key = Encoding.UTF8.GetBytes("test-signing-key-32-bytes-12345");
        var capture = new CaptureSink();
        var kernel = new GovernanceKernel(new GovernanceOptions
        {
            EnableAudit = true,
            EventSink = capture,
            EventSigningKey = key,
        });

        kernel.EvaluateToolCall("did:agentmesh:agent-1", "data.read");
        await Task.Delay(50);

        var evt = capture.Events.FirstOrDefault();
        Assert.NotNull(evt);
        Assert.NotEmpty(evt!.Signature);
        Assert.True(evt.VerifySignature(key));
    }

    [Fact]
    public void GovernanceKernel_WithoutEventSink_EventSinkPropertyIsNull()
    {
        var kernel = new GovernanceKernel();
        Assert.Null(kernel.EventSink);
    }

    [Fact]
    public void GovernanceKernel_WithEventSink_EventSinkPropertyIsSet()
    {
        var capture = new CaptureSink();
        var kernel = new GovernanceKernel(new GovernanceOptions { EventSink = capture });
        Assert.Same(capture, kernel.EventSink);
    }

    [Fact]
    public async Task GovernanceKernel_WithEventSink_PolicyViolation_ForwardsPolicyBreachCategory()
    {
        var yaml = @"
apiVersion: governance.toolkit/v1
name: no-shell-policy
default_action: allow
rules:
  - name: block-shell
    condition: ""tool_name == 'shell:rm'""
    action: deny
    priority: 10
";
        var capture = new CaptureSink();
        var kernel = new GovernanceKernel(new GovernanceOptions
        {
            EnableAudit = true,
            EventSink = capture,
        });
        kernel.LoadPolicyFromYaml(yaml);

        kernel.EvaluateToolCall("did:agentmesh:agent-1", "shell:rm");
        await Task.Delay(50);

        // Should include a PolicyBreach or ToolInvocation event
        var hasRelevantEvent = capture.Events.Any(e =>
            e.Type == "ai.agentmesh.policy.breach" ||
            e.Type == "ai.agentmesh.tool.invocation");

        Assert.True(hasRelevantEvent, "Expected a policy breach or tool invocation event");
    }
}
