---
name: container-k8s
description: Container & Kubernetes security — exposed API/kubelet, weak RBAC, privileged pods, registry exposure, escape. CLD06.
allowed-tools: Read, Grep, Glob, Bash
---

# Containers & Kubernetes Skill (CLD06)

Managed clusters (EKS/GKE/AKS) and exposed container infrastructure. Goal: from
exposed control plane / weak RBAC / a foothold pod to cluster or node compromise.

## Methodology

### Step 1: Exposure discovery
Exposed kube-apiserver (6443/443), kubelet (10250), etcd (2379), dashboard,
container registries, Docker API (2375). `kube-hunter` for remote checks.

### Step 2: Authn/authz
Anonymous API access (`kubectl --insecure-skip-tls-verify get pods` against an open
API), over-permissive RBAC (`kubectl auth can-i --list`), default service-account
tokens mounted in pods, `system:anonymous`/`system:unauthenticated` bindings.

### Step 3: From a pod foothold
Read the mounted SA token (`/var/run/secrets/kubernetes.io/serviceaccount/token`),
query the API with it, enumerate secrets (`kubectl get secrets -o yaml`), and reach
the **cloud metadata service** from the node (chain to `metadata-ssrf`).

### Step 4: Privileged-pod / escape paths
`privileged: true`, `hostPID`/`hostNetwork`, `hostPath` mounts, added capabilities,
writable docker socket — node breakout. Demonstrate non-destructively (read a node
file, not damage).

### Step 5: Cloud linkage
Cluster node/IAM roles (IRSA / workload identity) → cloud privesc via `iam-privesc`.

## Validate (negative control)
- **Attack:** show real cluster access — list secrets via an over-privileged SA, or
  reach the node/cloud creds from a pod.
- **Negative control:** a properly-scoped SA / `can-i` returns "no" for the same
  action. Distinguishes the misconfig from your own admin kubeconfig.

## Evidence to capture
The exposed endpoint / RBAC output / SA token usage and the access it yields
(redacted secrets). Note the cluster + cloud account.

## False-positive traps
- You used an admin kubeconfig, not the weak SA (re-test as the SA).
- API reachable but authn enforced (anonymous denied).
- `privileged` pod in a single-tenant node you already own — limited extra impact.

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh` only after proving cluster/node access with a negative control.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent nimbus \
  --id NIM-NNN --state confirmed --method manual-repro --method negative-control \
  --negative-control "default SA can 'get secrets' cluster-wide (kubectl auth can-i yes + dump); a scoped SA returns can-i no" --by nimbus
```
