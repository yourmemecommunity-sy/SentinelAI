# Kubernetes (Helm)

**Status: VERIFIED on a real cluster (kind v0.30.0, default node image) on 2026-09-23.** Never deployed to a managed cloud cluster —
nothing about EKS/AKS/GKE specifics is claimed here.

The chart is `infrastructure/helm/sentinel-ai` (see its README for the value reference). `scripts/development/k8s-verify.sh`
is the script that produced the verification below; it is re-runnable.

## Install

```bash
kubectl create namespace sentinel
kubectl -n sentinel create secret generic sentinel-secrets --from-env-file=secrets.env   # keys: chart README
helm install sentinel infrastructure/helm/sentinel-ai -n sentinel \
  --set secrets.existingSecret=sentinel-secrets \
  --set images.api.repository=ghcr.io/acme/sentinel-ai/api --set images.api.tag=1.0.0 \
  --wait --timeout 10m
```

Production also wants: `postgres.bundled.enabled=false` + `postgres.external.host=...` (managed database),
`redis.bundled.enabled=false` + `redis.external.host=...`, and an Ingress of your own in front of the `-api` and
`-dashboard` Services (the chart deliberately ships no Ingress: TLS, hostnames and WAF are site decisions).

## What the manifests enforce

| Property | How |
|---|---|
| No root, no capabilities, read-only root filesystem | Every SentinelAI container: `runAsUser` 1000/10001, `capabilities.drop: [ALL]`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault` |
| No service-account token in pods | `automountServiceAccountToken: false` |
| Component isolation | NetworkPolicies: default-deny for the release, then one policy per component listing only the peers it needs |
| No SSRF pivot from the gateway | The gateway's egress policy allows 443 to public addresses only: RFC1918, CGNAT **and 169.254.0.0/16 (cloud metadata) are excluded** |
| Migrations run once, safely | A Job per release revision holds the database OWNER credentials and a PostgreSQL advisory lock; retries and overlapping upgrades cannot race |
| The gateway never holds owner credentials | Gateway pods run `db/wait-for-schema.mjs` as the restricted role in an init container and start only when the schema they ship with is applied |
| Memory and pid limits | Set per component in `values.yaml` |

ClamAV (optional, `documentScanner.enabled=true`) is the one exception: its upstream entrypoint starts as root to prepare
the signature directory and then drops privileges, so it keeps `CHOWN, SETUID, SETGID, DAC_OVERRIDE, FOWNER` and a
writable filesystem. This is recorded in `infrastructure/.trivyignore.yaml` and re-checked on every verification run.

## Verification performed (2026-09-23, kind)

```
bash scripts/development/k8s-verify.sh --terraform      # 29 checks, all passed
```

* `helm lint`, render (27 objects), and a render **without** secrets is refused rather than silently deploying;
* `kubeconform -strict` against the Kubernetes 1.31 schemas: 27/27 valid;
* Trivy misconfiguration scan: no MEDIUM+ finding in the manifests SentinelAI controls; with bundled ClamAV the only
  findings are its three documented ones;
* installed on a real cluster with `--wait`: every workload became Ready; the migration Job applied 8 migrations and
  provisioned the restricted role;
* every container inspected **in the cluster**: non-root, read-only rootfs, no capabilities, no privilege escalation;
* in-cluster end to end: a secret is BLOCKED, PII is masked, an unconfigured provider is blocked (not proxied), and
  organization B sees none of organization A's events;
* scaling the security engine to zero: requests fail **closed** (`BLOCK`/`engine_unreachable`) and `/ready` returns 503;
  scaling it back up recovers;
* NetworkPolicy enforcement, from an unauthorized pod in the same namespace: token vault, PostgreSQL and Redis
  unreachable; the gateway reachable.

## Known gaps

* No HorizontalPodAutoscaler, PodDisruptionBudget or Ingress in the chart yet (`docs/future-roadmap.md`).
* Single-replica bundled PostgreSQL: evaluation only, no HA, no backups. Use a managed database.
* Verified on one kind node. Multi-node scheduling, rolling upgrades under load and node failure are **NOT VERIFIED**.
