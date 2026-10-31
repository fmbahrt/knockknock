{{- define "rendezvous.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "rendezvous.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "rendezvous.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "rendezvous.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: knockknock
{{- end }}

{{- define "rendezvous.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rendezvous.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "rendezvous.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "rendezvous.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "rendezvous.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{/* Name of the kubernetes.io/tls Secret the server reads. */}}
{{- define "rendezvous.tlsSecretName" -}}
{{- if eq .Values.tls.mode "secret" }}
{{- required "tls.secret.name is required when tls.mode is secret" .Values.tls.secret.name }}
{{- else }}
{{- printf "%s-tls" (include "rendezvous.fullname" .) }}
{{- end }}
{{- end }}

{{- define "rendezvous.serviceType" -}}
{{- if .Values.service.type }}
{{- .Values.service.type }}
{{- else if .Values.gateway.enabled }}
{{- "ClusterIP" }}
{{- else }}
{{- "LoadBalancer" }}
{{- end }}
{{- end }}

{{- define "rendezvous.gatewayName" -}}
{{- include "rendezvous.fullname" . }}
{{- end }}
