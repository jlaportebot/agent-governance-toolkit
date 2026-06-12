# AGT on Sovereign OpenShift: Air-Gap Deployment Guide

Deploy the Agent Governance Toolkit on a sovereign or air-gapped OpenShift cluster with
no external attestation service dependency. Covers multi-tenant carve-outs, bring-your-own
container (BYO-container) deployment, and post-quantum cryptographic enforcement for
deployments without TEE hardware.

> **Use cases:** sovereign cloud (on-prem data centers, bare-metal neo-cloud), defense
> workloads, regulated industries requiring data-residency enforcement, and any deployment
> where cloud-hosted attestation services are unavailable or untrusted.

> **See also:** [AKS Deployment](azure-container-apps.md) | [GCP GKE](gcp-gke.md) |
> [Sidecar Pattern](openclaw-sidecar.md)

---

## Table of Contents

- [Architecture](#architecture)
- [Air-Gap Considerations](#air-gap-considerations)
- [Multi-Tenant Carve-Outs](#multi-tenant-carve-outs)
- [BYO-Container Deployment](#byo-container-deployment)
- [Policy ConfigMap for Sovereign Context](#policy-configmap-for-sovereign-context)
- [OpenShift Manifests](#openshift-manifests)
- [Post-Quantum Cryptographic Enforcement](#post-quantum-cryptographic-enforcement)
- [Data Residency Enforcement](#data-residency-enforcement)
- [TRACE Trust Record Configuration](#trace-trust-record-configuration)
- [Audit and Compliance](#audit-and-compliance)

---

## Architecture

AGT runs as a sidecar alongside each agent workload. On sovereign OpenShift, the governance
sidecar is deployed inside the same pod as the agent container. Policy bundles load from a
ConfigMap. Audit logs are persisted to a local PVC. No external services are required --
the governance sidecar is fully self-contained.

```
+-----------------------------------------------------------------+
|  OpenShift Namespace: agent-governed-<tenant>                   |
|                                                                 |
|  +------------------------+   +-----------------------------+  |
|  |  Agent Container        |   |  AGT Governance Sidecar     |  |
|  |  (BYO workload)         |   |                             |  |
|  |                         |   |  Agent OS  -- policy engine |  |
|  |  Any language/runtime   |   |  AgentMesh -- identity      |  |
|  |  No AGT code required   |   |  Agent SRE -- SLOs          |  |
|  |                         |   |  Agent Runtime -- rings     |  |
|  |  Tool call ------------->   |  <- Cedar/OPA evaluation    |  |
|  |             <-----------    |  -> Allow / Deny            |  |
|  |                         |   |                             |  |
|  |  localhost:8080          |   |  localhost:8081 (proxy)     |  |
|  |                         |   |  localhost:9091 (metrics)   |  |
|  +------------------------+   +-----------------------------+  |
|            |                               |                   |
|            v                               v                   |
|       [Agent PVC]               [Audit PVC] + [Policy CM]      |
|                                                                 |
+-----------------------------------------------------------------+
         |
         v
  [On-prem attestation verifier]  <- AMD SEV-SNP / Intel TDX
  (no cloud attestation service required)
```

In the air-gap variant, the built-in attestation verifier anchors directly to AMD SEV-SNP
or Intel TDX silicon roots of trust -- no Azure AAS, no GCP attestation endpoint, no
external network call required. The same cryptographic guarantees apply on bare metal
as in cloud.

---

## Air-Gap Considerations

The governance sidecar requires **no outbound network access** for core functionality:

| Component | Default | Air-Gap |
|-----------|---------|---------|
| Policy evaluation | ConfigMap (local) | Same -- no change |
| Audit log write | PVC (local) | Same -- no change |
| TEE attestation | Azure AAS / GCP | Built-in attestation verifier (on-prem) |
| Identity (DID) | Mesh network | Local DID registry (ConfigMap) |
| TRACE signing | Ed25519 (local key) | Same -- no change |
| Metrics | stdout / Prometheus | Same -- scrape locally |

**Post-quantum fallback (no TEE):** On hardware without AMD SEV-SNP or Intel TDX, a
post-quantum cryptographic library implementing NIST FIPS 203/204 (ML-KEM/ML-DSA) can
provide cryptographic policy enforcement. Policies are bundle-signed with a post-quantum
key pair. The bundle signature appears in the TRACE Trust Record as `policy.pqc_signature`.
See [Post-Quantum Cryptographic Enforcement](#post-quantum-cryptographic-enforcement).

---

## Multi-Tenant Carve-Outs

Each tenant gets an isolated OpenShift namespace with its own:
- Policy ConfigMap (tenant-specific rules, data classification labels)
- Audit PVC (no cross-tenant log access)
- AgentMesh identity (scoped DID, non-overlapping trust domains)
- Resource quotas on the governance sidecar CPU/memory

```yaml
# One namespace per tenant
apiVersion: v1
kind: Namespace
metadata:
  name: agent-governed-tenant-a
  labels:
    agentmesh.io/tenant: tenant-a
    agentmesh.io/data-residency: us-east-1   # enforced by policy + TRACE
---
apiVersion: v1
kind: Namespace
metadata:
  name: agent-governed-tenant-b
  labels:
    agentmesh.io/tenant: tenant-b
    agentmesh.io/data-residency: eu-west-1
```

The governance sidecar reads its tenant label from the pod's downward-API environment and
scopes all identity operations (DID resolution, trust score evaluation) to that tenant.
Cross-tenant tool calls are denied by a namespace-boundary policy rule included in the
default policy bundle.

---

## BYO-Container Deployment

The agent container is customer-provided. No AGT code is required inside the agent image.
The governance proxy intercepts tool calls at the HTTP layer -- the agent calls
`http://localhost:8081/<tool>` instead of the upstream tool URL directly.

The only agent-side change is the proxy endpoint:

```python
# Before: call upstream tool directly
response = requests.post("https://upstream-api/tool", json=payload)

# After: route through governance proxy
response = requests.post("http://localhost:8081/tool", json=payload)
# The sidecar evaluates policy, logs the call, and proxies to upstream
```

The sidecar adds:
- Pre-call Cedar/OPA policy evaluation
- Execution ring classification (`X-AGT-Ring` response header)
- SHA-256 hash-chain audit entry
- TRACE Trust Record accumulation

No changes to the agent's business logic, no AGT SDK import required.

---

## Policy ConfigMap for Sovereign Context

A policy bundle for a sovereign AI workload must enforce data residency, tool allowlisting,
and require hardware attestation for sensitive data access. The following is a template:

```cedar
// Sovereign workload policy bundle
// version: sovereign-v1.0
// Cedar default-deny: anything not explicitly permitted is denied.

// Rule 1: inference is permitted within the declared data-residency boundary.
permit (
  principal,
  action == Action::"Inference.run",
  resource
) when {
  context has workflow_id &&
  context has data_residency &&
  context.data_residency == "your-region"
};

// Rule 2: data export outside the residency boundary requires explicit approval.
@id("cross-border-data-export")
@reason("data-residency-violation")
@regulation("your-data-residency-regulation")
forbid (
  principal,
  action == Action::"Data.export",
  resource
) when {
  context has data_residency &&
  context.data_residency != "your-region"
};

// Rule 3: sensitive data tools require hardware attestation.
@id("require-attested-runtime")
@reason("attested-runtime-required")
forbid (
  principal,
  action,
  resource
) when {
  context.data_class == "sensitive" &&
  context.attestation_platform == "unknown"
};

// Rule 4: Ring 1 (irreversible) actions require human approval.
@id("ring1-require-approval")
@reason("human-approval-required-for-irreversible-action")
forbid (
  principal,
  action,
  resource
) when {
  context.execution_ring == "ring1" &&
  !(context has approval_token)
};
```

Apply as a ConfigMap:

```bash
kubectl create configmap sovereign-policies \
  --from-file=policies/ \
  -n agent-governed-<tenant>
```

---

## OpenShift Manifests

### Governance Sidecar Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: governed-agent
  namespace: agent-governed-tenant-a
spec:
  replicas: 1
  selector:
    matchLabels:
      app: governed-agent
  template:
    metadata:
      labels:
        app: governed-agent
        agentmesh.io/governed: "true"
    spec:
      containers:
      # Agent container -- BYO image, no AGT code required
      - name: agent
        image: <YOUR_REGISTRY>/your-agent:latest
        env:
        - name: GOVERNANCE_PROXY_URL
          value: "http://localhost:8081"
        ports:
        - containerPort: 8080

      # AGT governance sidecar
      - name: governance-sidecar
        image: <YOUR_REGISTRY>/agentmesh/governance-sidecar:0.3.0
        env:
        - name: AGT_TENANT_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        - name: AGT_ATTESTATION_PROVIDER
          value: "builtin"     # no cloud service -- built-in verifier
        - name: AGT_POLICY_PATH
          value: "/policies"
        - name: AGT_AUDIT_PATH
          value: "/audit"
        - name: AGT_DATA_RESIDENCY
          valueFrom:
            fieldRef:
              fieldPath: metadata.labels['agentmesh.io/data-residency']
        ports:
        - containerPort: 8081   # governance proxy
          name: proxy
        - containerPort: 9091   # metrics
          name: metrics
        volumeMounts:
        - name: policies
          mountPath: /policies
          readOnly: true
        - name: audit-storage
          mountPath: /audit
        readinessProbe:
          httpGet:
            path: /ready
            port: 8081
          initialDelaySeconds: 5
        livenessProbe:
          httpGet:
            path: /health
            port: 8081
          periodSeconds: 30

      volumes:
      - name: policies
        configMap:
          name: sovereign-policies
      - name: audit-storage
        persistentVolumeClaim:
          claimName: audit-pvc-tenant-a
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: audit-pvc-tenant-a
  namespace: agent-governed-tenant-a
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: sovereign-storage   # on-prem storage class
```

### OpenShift Security Context Constraint

On OpenShift, the governance sidecar needs a restricted SCC. It does not require
`privileged` -- it runs as a non-root user:

```yaml
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: agt-sidecar-scc
allowPrivilegedContainer: false
allowPrivilegeEscalation: false
runAsUser:
  type: MustRunAsNonRoot
seLinuxContext:
  type: MustRunAs
fsGroup:
  type: MustRunAs
  ranges:
  - min: 1000
    max: 65535
users:
- system:serviceaccount:agent-governed-tenant-a:governed-agent-sa
```

---

## Post-Quantum Cryptographic Enforcement

On hardware without AMD SEV-SNP or Intel TDX, a post-quantum cryptographic library
implementing NIST FIPS 203/204 (ML-KEM-768 for key encapsulation, ML-DSA-65 for signing)
can provide cryptographic policy enforcement. The policy bundle is signed with a
post-quantum key pair and the signature is verifiable without TEE hardware.

Configure in the sidecar environment:

```yaml
- name: AGT_CRYPTO_PROVIDER
  value: "pqclib"
- name: AGT_PQCLIB_SIGNING_KEY_PATH
  value: "/keys/ml-dsa-65-private.key"
- name: AGT_PQCLIB_VERIFY_KEY_PATH
  value: "/keys/ml-dsa-65-public.key"
```

The bundle signature appears in the TRACE Trust Record as `policy.pqc_signature`. Verifiers
can validate the signature using only the published public key -- no TEE hardware required
at verification time. This mode is suitable for air-gapped deployments and environments
with NIST PQC migration requirements.

---

## Data Residency Enforcement

The TRACE Trust Record produced at the end of each session includes:

```json
{
  "runtime": {
    "platform": "amd-sev-snp",
    "region": "your-region",
    "provider": "your-platform"
  },
  "policy": {
    "version": "sovereign-v1.0",
    "enforcement_mode": "enforce",
    "bundle_hash": "sha256:..."
  }
}
```

The `runtime.region` field is set from the pod's `agentmesh.io/data-residency` label and
is cryptographically bound to the hardware attestation measurement. A verifier can confirm
that a TRACE record claiming a specific region was produced on hardware in that region --
the hardware measurement from a different deployment would not match.

---

## TRACE Trust Record Configuration

```yaml
# cmcp-config.yaml for sovereign deployment
policy_bundle_path: /policies
catalog_path: /catalog.json
listen_addr: 0.0.0.0:8443
audit_db_path: /audit/audit.db
attestation:
  provider: builtin
  enforcement_mode: enforcing
  validity_seconds: 3600
trace:
  eat_profile: "tag:agentrust.io,2026:trace-v0.1"
  runtime_provider: your-platform        # set to your platform identifier
  runtime_region: your-region            # set to your data residency region
  crypto_provider: pqclib                # or tpm2 / amd-sev-snp / intel-tdx
  scitt_endpoint: ""                     # leave empty for air-gap; set for transparency log
```

---

## Audit and Compliance

All governance decisions are recorded in a SHA-256 hash-chained audit log at
`/audit/audit.db`. The chain is append-only -- modifications break all downstream
hashes (tamper self-reporting).

**Produce a signed compliance artifact:**

```bash
agt verify --audit-db /audit/audit.db --output compliance-report.json
```

**Anchor the audit chain to a SCITT transparency log** (when network is available):

```bash
agt scitt-anchor \
  --audit-db /audit/audit.db \
  --endpoint https://scitt.your-sovereign-cloud/
```

**Replay a policy change against production audit history** before activating:

```bash
agt replay \
  --audit-db /audit/audit.db \
  --policy-bundle ./policies-v2/ \
  --output replay-diff.json
```

The replay diff shows which previously-allowed actions would now be denied and which
previously-denied actions would now be allowed. Required sign-off before activation.
