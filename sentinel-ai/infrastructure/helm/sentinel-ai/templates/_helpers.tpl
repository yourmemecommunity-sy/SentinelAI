{{- define "sentinel.fullname" -}}{{ .Release.Name | trunc 40 | trimSuffix "-" }}{{- end -}}

{{- define "sentinel.labels" -}}
app.kubernetes.io/part-of: sentinel-ai
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{/* selector labels for one component: (dict "root" . "c" "api") */}}
{{- define "sentinel.selector" -}}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .c }}
{{- end -}}

{{- define "sentinel.image" -}}{{ .root.Values.global.imageRegistry }}{{ .img.repository }}:{{ .img.tag }}{{- end -}}

{{- define "sentinel.secretName" -}}
{{- if .Values.secrets.create -}}{{ include "sentinel.fullname" . }}-secrets
{{- else -}}{{ required "secrets.existingSecret is required (or set secrets.create=true for development)" .Values.secrets.existingSecret }}
{{- end -}}
{{- end -}}

{{- define "sentinel.secretEnv" -}}
- name: {{ .name }}
  valueFrom:
    secretKeyRef:
      name: {{ include "sentinel.secretName" .root }}
      key: {{ .key }}
      {{- if .optional }}
      optional: true
      {{- end }}
{{- end -}}

{{- define "sentinel.pgHost" -}}
{{- if .Values.postgres.bundled.enabled -}}{{ include "sentinel.fullname" . }}-postgres{{- else -}}{{ required "postgres.external.host is required when the bundled PostgreSQL is disabled" .Values.postgres.external.host }}{{- end -}}
{{- end -}}
{{- define "sentinel.pgPort" -}}{{ if .Values.postgres.bundled.enabled }}5432{{ else }}{{ .Values.postgres.external.port }}{{ end }}{{- end -}}
{{- define "sentinel.redisHost" -}}
{{- if .Values.redis.bundled.enabled -}}{{ include "sentinel.fullname" . }}-redis{{- else -}}{{ required "redis.external.host is required when the bundled Redis is disabled" .Values.redis.external.host }}{{- end -}}
{{- end -}}
{{- define "sentinel.redisPort" -}}{{ if .Values.redis.bundled.enabled }}6379{{ else }}{{ .Values.redis.external.port }}{{ end }}{{- end -}}
{{- define "sentinel.clamavHost" -}}
{{- if .Values.clamav.bundled.enabled -}}{{ include "sentinel.fullname" . }}-clamav{{- else -}}{{ required "clamav.external.host is required when the bundled ClamAV is disabled" .Values.clamav.external.host }}{{- end -}}
{{- end -}}
{{- define "sentinel.clamavPort" -}}{{ if .Values.clamav.bundled.enabled }}3310{{ else }}{{ .Values.clamav.external.port }}{{ end }}{{- end -}}

{{/* Pod-level hardening shared by every SentinelAI workload. */}}
{{- define "sentinel.podSecurity" -}}
automountServiceAccountToken: false
securityContext:
  runAsNonRoot: true
  seccompProfile: { type: RuntimeDefault }
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets: {{ toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/* Container-level hardening: read-only root, no capabilities, no privilege escalation, fixed non-root uid. */}}
{{- define "sentinel.containerSecurity" -}}
securityContext:
  runAsUser: {{ .uid }}
  runAsGroup: {{ .uid }}
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities: { drop: [ALL] }
{{- end -}}

{{- define "sentinel.probes" -}}
readinessProbe:
  httpGet: { path: {{ .ready }}, port: http }
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
livenessProbe:
  httpGet: { path: {{ .live }}, port: http }
  initialDelaySeconds: 20
  periodSeconds: 20
  timeoutSeconds: 5
  failureThreshold: 5
{{- end -}}

{{/* NetworkPolicy peer selector for one component: (dict "inst" .Release.Name "c" "api") */}}
{{- define "sentinel.np.peer" -}}
- podSelector: { matchLabels: { app.kubernetes.io/instance: {{ .inst }}, app.kubernetes.io/component: {{ .c }} } }
{{- end -}}
