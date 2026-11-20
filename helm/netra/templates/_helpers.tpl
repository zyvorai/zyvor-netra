{{- define "netra.name" -}}netra{{- end -}}
{{- define "netra.labels" -}}
app.kubernetes.io/name: {{ include "netra.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "netra.authSecretName" -}}
{{- if .Values.auth.existingSecret -}}
{{ .Values.auth.existingSecret }}
{{- else -}}
netra-auth
{{- end -}}
{{- end -}}
{{- define "netra.lokiLabels" -}}
{{- $pairs := list -}}
{{- range $k, $v := .Values.loki.labels -}}
{{- $pairs = append $pairs (printf "%s=%s" $k ($v | toString)) -}}
{{- end -}}
{{- join "," $pairs -}}
{{- end -}}
{{- define "netra.mtlsMode" -}}
{{- $m := (.Values.mtls.mode | default "off" | toString | lower) -}}
{{- if not (has $m (list "off" "optional" "required")) -}}
{{- fail (printf "mtls.mode=%q: want off, optional or required" $m) -}}
{{- end -}}
{{- if and (ne $m "off") (not .Values.tls.enabled) -}}
{{- fail "mtls.mode needs tls.enabled=true (a client certificate cannot be requested over plain HTTP)" -}}
{{- end -}}
{{- if and (ne $m "off") (not (include "netra.mtlsSecret" .)) -}}
{{- fail "mtls.mode needs mtls.secretName (a Secret with ca.crt, tls.crt, tls.key) or mtls.certManager.enabled with an issuerRef" -}}
{{- end -}}
{{- $m -}}
{{- end -}}
{{- define "netra.mtlsSecret" -}}
{{- if .Values.mtls.secretName -}}
{{ .Values.mtls.secretName }}
{{- else if .Values.mtls.certManager.enabled -}}
netra-agent-mtls
{{- end -}}
{{- end -}}
