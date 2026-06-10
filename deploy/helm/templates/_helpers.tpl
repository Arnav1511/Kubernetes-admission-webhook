{{- define "k8s-policy-webhook.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "k8s-policy-webhook.selectorLabels" -}}
app.kubernetes.io/name: k8s-policy-webhook
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "k8s-policy-webhook.labels" -}}
{{ include "k8s-policy-webhook.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "k8s-policy-webhook.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "k8s-policy-webhook.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- required "serviceAccount.name is required when serviceAccount.create=false" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "k8s-policy-webhook.tlsSecretName" -}}
{{- if .Values.certManager.enabled -}}
{{- default (printf "%s-tls" (include "k8s-policy-webhook.fullname" .)) .Values.certManager.certificate.secretName -}}
{{- else -}}
{{- required "tls.existingSecretName is required when certManager.enabled=false" .Values.tls.existingSecretName -}}
{{- end -}}
{{- end -}}

{{- define "k8s-policy-webhook.certificateName" -}}
{{- default (printf "%s-serving-cert" (include "k8s-policy-webhook.fullname" .)) .Values.certManager.certificate.name -}}
{{- end -}}

{{- define "k8s-policy-webhook.issuerName" -}}
{{- if .Values.certManager.issuer.create -}}
{{- default (printf "%s-selfsigned" (include "k8s-policy-webhook.fullname" .)) .Values.certManager.issuer.name -}}
{{- else -}}
{{- required "certManager.issuer.name is required when certManager.issuer.create=false" .Values.certManager.issuer.name -}}
{{- end -}}
{{- end -}}
