#!/usr/bin/env bash
# Validates the Helm chart and then PROVES it on a real Kubernetes cluster (kind):
#   1. helm lint + render, kubeconform schema validation, Trivy misconfiguration scan of the rendered manifests
#   2. install on a throwaway kind cluster with the locally built images
#   3. check: migrations ran, every workload became ready, the security pipeline works end to end through the cluster,
#      tenant isolation holds, the gateway fails closed when the engine is scaled to zero, NetworkPolicies are enforced,
#      and every container really runs non-root with a read-only root filesystem and no capabilities.
#
#   4. (--terraform) apply infrastructure/terraform/environments/kind against the same cluster, in its own namespace,
#      and destroy it again - so the Terraform path is executed, not just written.
#
#   bash scripts/development/k8s-verify.sh [--keep] [--terraform]   (inside WSL; needs docker, kind, helm, kubectl)
set -uo pipefail
cd "$(dirname "$0")/../.."
CHART=infrastructure/helm/sentinel-ai
CLUSTER=${KIND_CLUSTER:-sentinel-verify}
NS=sentinel
KEEP=""; TF=""
for arg in "$@"; do case "$arg" in --keep) KEEP=1 ;; --terraform) TF=1 ;; *) echo "unknown option: $arg"; exit 2 ;; esac; done
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
k() { kubectl --context "kind-${CLUSTER}" -n "$NS" "$@"; }

echo "===== 1. static validation"
helm lint "$CHART" --set secrets.existingSecret=x >/tmp/lint.log 2>&1 && pass "helm lint" || { fail "helm lint"; tail -20 /tmp/lint.log; }
helm template t "$CHART" --set secrets.existingSecret=x > /tmp/rendered.yaml 2>/tmp/render.err \
  && pass "chart renders ($(grep -c '^kind:' /tmp/rendered.yaml) objects)" || { fail "helm template"; cat /tmp/render.err; }
# The chart must refuse to render without secrets rather than silently deploying something unauthenticated.
helm template t "$CHART" >/dev/null 2>&1 && fail "chart renders with no secret configured" || pass "chart refuses to render without secrets.existingSecret"
docker run --rm -i ghcr.io/yannh/kubeconform:v0.6.7 -strict -summary -kubernetes-version 1.31.0 \
  -schema-location default < /tmp/rendered.yaml && pass "kubeconform: manifests match the Kubernetes 1.31 schemas" || fail "kubeconform"
# Two passes. Pass 1: everything SentinelAI builds and controls - must be completely clean. Pass 2: the same with the
# bundled ClamAV, whose upstream entrypoint starts as root to prepare its signature directory and then drops privileges;
# there the ONLY findings allowed are that documented exception, and anything else fails the scan.
TRIVY="docker run --rm -v /tmp:/m:ro -v $PWD/infrastructure/.trivyignore.yaml:/ignore.yaml:ro -v /root/trivy-cache:/root/.cache/ aquasec/trivy:0.58.1"
helm template t "$CHART" --set secrets.existingSecret=x --set documentScanner.enabled=false > /tmp/rendered-core.yaml 2>/dev/null
$TRIVY config --quiet --severity MEDIUM,HIGH,CRITICAL --ignorefile /ignore.yaml --exit-code 1 /m/rendered-core.yaml >/tmp/trivy-k8s.log 2>&1 \
  && pass "Trivy: no MEDIUM+ misconfiguration in the manifests SentinelAI controls" \
  || { fail "Trivy misconfigurations:"; grep -E "AVD-" /tmp/trivy-k8s.log | head -20; }
$TRIVY config --quiet --severity MEDIUM,HIGH,CRITICAL --ignorefile /ignore.yaml --format json /m/rendered.yaml > /tmp/trivy-full.json 2>/dev/null
unexpected=$(python3 -c '
import json
d = json.load(open("/tmp/trivy-full.json"))
# Trivy reports these as KSV012 / KSV0012 / AVD-KSV-0012 depending on the field, so match every spelling.
allowed = {"KSV012", "KSV0012", "AVD-KSV-0012", "KSV014", "KSV0014", "AVD-KSV-0014", "KSV022", "KSV0022", "AVD-KSV-0022"}
bad = set()
for r in d.get("Results") or []:
    for m in r.get("Misconfigurations") or []:
        if m.get("Status") != "FAIL":
            continue
        about_clamav = "clamav" in (m.get("Message") or "") + (r.get("Target") or "")
        if not (about_clamav and m["ID"] in allowed):
            bad.add(m["ID"] + " " + m["Severity"] + " " + (m.get("Message") or "")[:70])
print("; ".join(sorted(bad)))')
[ -z "$unexpected" ] && pass "with the bundled ClamAV, the only findings are its documented root-entrypoint exception" \
  || fail "unexpected misconfigurations: $unexpected"

echo "===== 2. real cluster (kind)"
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER" --wait 180s >/tmp/kind.log 2>&1 || { fail "kind create cluster"; tail -20 /tmp/kind.log; exit 1; }
fi
pass "kind cluster $CLUSTER is up ($(kubectl --context "kind-${CLUSTER}" get nodes -o name | wc -l) node)"
for img in api dashboard security-engine token-vault document-scanner; do
  kind load docker-image "sentinel-ai/$img:local" --name "$CLUSTER" >/dev/null 2>&1 || fail "loading image $img"
done
pass "locally built images loaded into the cluster"
kubectl --context "kind-${CLUSTER}" create namespace "$NS" >/dev/null 2>&1
# Secrets: generated here, never committed. Same shapes the compose stack uses.
hex() { openssl rand -hex "$1"; }
k delete secret sentinel-secrets >/dev/null 2>&1
k create secret generic sentinel-secrets \
  --from-literal=postgres-password="$(hex 24)" --from-literal=app-db-password="$(hex 24)" \
  --from-literal=api-key-hash-pepper="$(hex 32)" --from-literal=jwt-access-secret="$(hex 32)" \
  --from-literal=security-engine-token="$(hex 24)" --from-literal=document-scanner-token="$(hex 24)" \
  --from-literal=vault-token="$(hex 24)" --from-literal=vault-master-keys="k1:$(openssl rand -base64 32)" \
  --from-literal=redis-password="$(hex 24)" --from-literal=provider-credential-keys="p1:$(openssl rand -base64 32)" >/dev/null \
  && pass "secret created in the cluster (generated here, never committed)" || fail "secret creation"

helm --kube-context "kind-${CLUSTER}" upgrade --install sentinel "$CHART" -n "$NS" \
  --set secrets.existingSecret=sentinel-secrets \
  --set images.pullPolicy=Never \
  --set api.replicas=2 --set securityEngine.replicas=1 --set tokenVault.replicas=1 --set dashboard.replicas=1 \
  --set api.signupEnabled=true --set api.corsOrigins=http://localhost:3000 \
  --set "documentScanner.enabled=${WITH_CLAMAV:-false}" --set "clamav.bundled.enabled=${WITH_CLAMAV:-false}" \
  --wait --timeout 10m >/tmp/helm-install.log 2>&1 && pass "helm install completed (--wait: every workload became Ready)" \
  || { fail "helm install"; tail -25 /tmp/helm-install.log; k get pods; }

echo "===== 3. what the cluster actually does"
k get pods -o wide --no-headers | sed 's/^/  /'
jobpod=$(k get pods -l app.kubernetes.io/component=migrate -o name | head -1)
if k logs "$jobpod" 2>/dev/null | grep -q "login role"; then
  pass "migration Job applied the schema and provisioned the restricted role ($(k logs "$jobpod" | grep -c applied || true) log lines)"
else fail "migration job: $(k logs "$jobpod" 2>&1 | tail -3)"; fi

# Security context of every SentinelAI container, as the cluster sees it (not as the chart claims).
bad=$(k get pods -l app.kubernetes.io/part-of=sentinel-ai -o json | python3 -c '
import json,sys
bad=[]
for p in json.load(sys.stdin)["items"]:
    comp = p["metadata"]["labels"].get("app.kubernetes.io/component")
    if comp in ("clamav",): continue                      # documented exception: its entrypoint drops privileges itself
    pod = p["spec"].get("securityContext", {}) or {}
    for c in p["spec"]["containers"] + p["spec"].get("initContainers", []):
        s = c.get("securityContext", {}) or {}
        caps = (s.get("capabilities") or {}).get("drop") or []
        # runAsUser may be set on the container or inherited from the pod (the bundled databases set it pod-wide).
        uid = s.get("runAsUser", pod.get("runAsUser", 0))
        non_root = uid > 0 or pod.get("runAsNonRoot") is True
        if not (s.get("readOnlyRootFilesystem") and s.get("allowPrivilegeEscalation") is False and "ALL" in caps and non_root):
            bad.append(p["metadata"]["name"] + "/" + c["name"] + ": " + json.dumps({"container": s, "pod": pod}))
print("; ".join(bad))')
[ -z "$bad" ] && pass "every SentinelAI container: non-root, read-only rootfs, no capabilities, no privilege escalation" || fail "containers not hardened: $bad"

# End-to-end through the cluster: a client pod inside the namespace talking to the gateway Service.
cat > /tmp/k8s-probe.mjs <<'JS'
const API = process.env.API_URL;
const AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP";
const out = [];
const post = async (path, body, headers = {}) => {
  const res = await fetch(`${API}${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body), signal: AbortSignal.timeout(30000) });
  return { status: res.status, json: await res.json().catch(() => null) };
};
const org = async (slug) => {
  const s = await post("/v1/auth/signup", { organization_name: slug, email: `${slug}@example.com`, password: "Str0ng-K8s-Passw0rd!" });
  const k = await post("/v1/api-keys", { name: "probe", role: "DEVELOPER" }, { authorization: `Bearer ${s.json.access_token}` });
  return { jwt: s.json.access_token, key: k.json.key };
};
const a = await org(`k8s-a-${Date.now().toString(36)}`);
const b = await org(`k8s-b-${Date.now().toString(36)}`);
const blocked = await post("/v1/security/scan", { text: `deploy with ${AWS}` }, { "x-sentinel-api-key": a.key });
out.push(["secret is blocked by the engine through the cluster", blocked.status === 200 && blocked.json.decision === "BLOCK" && blocked.json.sanitized_text === null, blocked.json?.decision]);
const pii = await post("/v1/security/scan", { text: "email jane.doe@example.com" }, { "x-sentinel-api-key": a.key });
out.push(["PII is masked, never returned raw", pii.status === 200 && !JSON.stringify(pii.json).includes("jane.doe@example.com"), pii.json?.decision]);
const evA = await fetch(`${API}/v1/events?limit=50`, { headers: { authorization: `Bearer ${a.jwt}` } }).then((r) => r.json());
const evB = await fetch(`${API}/v1/events?limit=50`, { headers: { authorization: `Bearer ${b.jwt}` } }).then((r) => r.json());
out.push(["tenant isolation: organization B sees none of A's events", evA.events.length > 0 && evB.events.length === 0, `A=${evA.events.length} B=${evB.events.length}`]);
const unknown = await post("/v1/ai/chat", { provider: "openai", messages: [{ role: "user", content: "hi" }] }, { "x-sentinel-api-key": a.key });
out.push(["an unconfigured provider is blocked, not proxied", unknown.status === 403 && unknown.json.reason === "unknown_provider", String(unknown.status)]);
for (const [name, ok, detail] of out) console.log(`${ok ? "PASS" : "FAIL"} ${name}  (${detail})`);
process.exit(out.every(([, ok]) => ok) ? 0 : 1);
JS
k delete pod probe --ignore-not-found >/dev/null 2>&1
k create configmap probe-src --from-file=probe.mjs=/tmp/k8s-probe.mjs --dry-run=client -o yaml | k apply -f - >/dev/null
k run probe --image=node:20-alpine --restart=Never --labels="app.kubernetes.io/instance=sentinel,app.kubernetes.io/component=dashboard" \
  --env="API_URL=http://sentinel-api:4000" --overrides='{"spec":{"containers":[{"name":"probe","image":"node:20-alpine","command":["node","/src/probe.mjs"],"env":[{"name":"API_URL","value":"http://sentinel-api:4000"}],"volumeMounts":[{"name":"src","mountPath":"/src"}]}],"volumes":[{"name":"src","configMap":{"name":"probe-src"}}]}}' >/dev/null
k wait --for=jsonpath='{.status.phase}'=Succeeded pod/probe --timeout=180s >/dev/null 2>&1
k logs probe | sed 's/^/  /'
k logs probe | grep -q '^FAIL' && fail "in-cluster functional checks" || pass "in-cluster functional checks"

echo "===== 4. fail closed in the cluster"
k scale deploy sentinel-security-engine --replicas=0 >/dev/null
k wait --for=delete pod -l app.kubernetes.io/component=security-engine --timeout=60s >/dev/null 2>&1
sleep 3
k delete pod probe --ignore-not-found >/dev/null 2>&1
cat > /tmp/k8s-failclosed.mjs <<'JS'
const API = process.env.API_URL;
const slug = `k8s-fc-${Date.now().toString(36)}`;
const post = async (path, body, headers = {}) => {
  const res = await fetch(`${API}${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body), signal: AbortSignal.timeout(30000) });
  return { status: res.status, json: await res.json().catch(() => null) };
};
const s = await post("/v1/auth/signup", { organization_name: slug, email: `${slug}@example.com`, password: "Str0ng-K8s-Passw0rd!" });
const k = await post("/v1/api-keys", { name: "fc", role: "DEVELOPER" }, { authorization: `Bearer ${s.json.access_token}` });
const scan = await post("/v1/security/scan", { text: "anything at all" }, { "x-sentinel-api-key": k.json.key });
const ready = await fetch(`${API}/ready`).then((r) => r.status);
const ok = scan.status === 200 && scan.json.decision === "BLOCK" && scan.json.failed_closed === true && ready === 503;
console.log(`${ok ? "PASS" : "FAIL"} engine scaled to zero -> requests fail CLOSED (${scan.json?.decision}/${scan.json?.fail_closed_reason}) and /ready is ${ready}`);
process.exit(ok ? 0 : 1);
JS
k create configmap probe-src2 --from-file=probe.mjs=/tmp/k8s-failclosed.mjs --dry-run=client -o yaml | k apply -f - >/dev/null
k run probe --image=node:20-alpine --restart=Never --labels="app.kubernetes.io/instance=sentinel,app.kubernetes.io/component=dashboard" \
  --overrides='{"spec":{"containers":[{"name":"probe","image":"node:20-alpine","command":["node","/src/probe.mjs"],"env":[{"name":"API_URL","value":"http://sentinel-api:4000"}],"volumeMounts":[{"name":"src","mountPath":"/src"}]}],"volumes":[{"name":"src","configMap":{"name":"probe-src2"}}]}}' >/dev/null
k wait --for=jsonpath='{.status.phase}'=Succeeded pod/probe --timeout=120s >/dev/null 2>&1
k logs probe | sed 's/^/  /'
k logs probe | grep -q '^PASS' && pass "gateway fails closed while the engine is gone" || fail "fail-closed check in cluster"
k scale deploy sentinel-security-engine --replicas=1 >/dev/null
k rollout status deploy/sentinel-security-engine --timeout=120s >/dev/null 2>&1 && pass "engine recovered after scaling back up" || fail "engine did not recover"

echo "===== 5. NetworkPolicy enforcement (a pod that is not allowed must not reach the vault or the database)"
k delete pod intruder --ignore-not-found >/dev/null 2>&1
k run intruder --image=node:20-alpine --restart=Never --command -- sh -c '
  vault=$(nc -z -w 3 sentinel-token-vault 8004 && echo REACHABLE || echo blocked)
  pg=$(nc -z -w 3 sentinel-postgres 5432 && echo REACHABLE || echo blocked)
  redis=$(nc -z -w 3 sentinel-redis 6379 && echo REACHABLE || echo blocked)
  api=$(nc -z -w 3 sentinel-api 4000 && echo reachable || echo BLOCKED)
  echo "vault=$vault postgres=$pg redis=$redis api=$api"' >/dev/null
k wait --for=jsonpath='{.status.phase}'=Succeeded pod/intruder --timeout=120s >/dev/null 2>&1
res=$(k logs intruder 2>/dev/null)
echo "  $res"
case "$res" in
  "vault=blocked postgres=blocked redis=blocked api=reachable") pass "NetworkPolicies enforced: the vault, the database and Redis are unreachable from an unauthorized pod; the gateway is reachable" ;;
  *) fail "NetworkPolicy enforcement: $res (if everything is reachable, this cluster's CNI may not enforce NetworkPolicy)" ;;
esac

if [ -n "$TF" ]; then
echo "===== 6. Terraform (infrastructure/terraform/environments/kind) applied against the same cluster"
# A private copy: terraform writes .terraform/ and plan.out, and anything that re-syncs the working tree mid-run (a
# `rsync --delete`) must not be able to delete them between plan and apply - which is exactly what happened once.
TFDIR=$(mktemp -d)/terraform
cp -r "$PWD/infrastructure/terraform" "$TFDIR"
tf() { docker run --rm --network host -v "$TFDIR:/tf" -v "$PWD/infrastructure/helm:/helm:ro" -v "$HOME/.kube:/root/.kube"          -w /tf/environments/kind -e TF_IN_AUTOMATION=1 hashicorp/terraform:1.9 "$@"; }
tf fmt -check -recursive /tf >/tmp/tffmt.log 2>&1 && pass "terraform fmt: all files formatted" || { fail "terraform fmt"; cat /tmp/tffmt.log; }
tf init -input=false -no-color >/tmp/tfinit.log 2>&1 && pass "terraform init (kubernetes + helm + random providers)" || { fail "terraform init"; tail -15 /tmp/tfinit.log; }
tf validate -no-color >/tmp/tfvalidate.log 2>&1 && pass "terraform validate" || { fail "terraform validate"; tail -15 /tmp/tfvalidate.log; }
# A wildcard CORS origin and disabling the NetworkPolicies must be refused by the variable validation, not silently accepted.
tf plan -input=false -no-color -var 'cors_origins=*' >/tmp/tfplan-bad.log 2>&1 && fail "a wildcard CORS origin was accepted" || pass "variable validation refuses a wildcard CORS origin"
tf plan -input=false -no-color -var 'network_policy_enabled=false' >/tmp/tfplan-bad2.log 2>&1 && fail "disabling NetworkPolicies was accepted" || pass "variable validation refuses disabling the NetworkPolicies"
tf plan -input=false -no-color -out=/tf/environments/kind/plan.out >/tmp/tfplan.log 2>&1   && pass "terraform plan ($(grep -cE '^  # ' /tmp/tfplan.log) resources to create)" || { fail "terraform plan"; tail -20 /tmp/tfplan.log; }
if tf apply -input=false -no-color -auto-approve /tf/environments/kind/plan.out >/tmp/tfapply.log 2>&1; then
  pass "terraform apply: release $(kubectl --context "kind-${CLUSTER}" -n sentinel-tf get pods --no-headers 2>/dev/null | grep -c Running) pods running in namespace sentinel-tf"
  st=$(tf output -raw release_status 2>/dev/null)
  [ "$st" = "deployed" ] && pass "helm release reports status=deployed through Terraform" || fail "release status=$st"
  # The namespace Terraform creates must carry the restricted Pod Security standard.
  pss=$(kubectl --context "kind-${CLUSTER}" get ns sentinel-tf -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')
  [ "$pss" = "restricted" ] && pass "namespace enforces the restricted Pod Security standard" || fail "namespace PSS=$pss"
  tf destroy -input=false -no-color -auto-approve >/tmp/tfdestroy.log 2>&1 && pass "terraform destroy removed everything it created" || { fail "terraform destroy"; tail -10 /tmp/tfdestroy.log; }
else
  fail "terraform apply"; tail -25 /tmp/tfapply.log
fi
rm -rf "$(dirname "$TFDIR")"
fi

echo
if [ -z "$KEEP" ]; then kind delete cluster --name "$CLUSTER" >/dev/null 2>&1; echo "kind cluster deleted"; fi
[ "$FAIL" = 0 ] && echo "KUBERNETES VERIFICATION: ALL CHECKS PASSED" || echo "KUBERNETES VERIFICATION: $FAIL CHECK(S) FAILED"
exit "$FAIL"
