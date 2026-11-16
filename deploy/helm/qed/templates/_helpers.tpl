{{/* Names and labels. */}}

{{- define "qed.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "qed.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "qed.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "qed.selectorLabels" . }}
app.kubernetes.io/version: {{ include "qed.imageTag" . | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "qed.selectorLabels" -}}
app.kubernetes.io/name: {{ include "qed.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "qed.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "qed.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
The image tag defaults to the chart's appVersion rather than `latest`. Every
decision the chain records carries an engine version, so "whatever was pushed
last" is not a thing an installed release should resolve to.
*/}}
{{- define "qed.imageTag" -}}
{{- default .Chart.AppVersion .Values.image.tag -}}
{{- end -}}

{{- define "qed.isPostgres" -}}
{{- eq .Values.evidence.backend "postgres" -}}
{{- end -}}

{{/*
The environment variable carrying one adapter's shared secret.

This must stay identical to `_secret_env_name` in qed/cli.py: an operator who
generates the secret with `qed adapters add` locally is told to export *that*
name, and a chart that picked a different one would produce a pod whose only
symptom is `readyz: false` next to an adapter that looks registered.

The context is the adapter id.
*/}}
{{- define "qed.adapterSecretEnv" -}}
{{- printf "QED_ADAPTER_SECRET_%s" (regexReplaceAll "[^A-Z0-9]" (upper .) "_") -}}
{{- end -}}

{{/*
The adapters `qed.yaml` will register: `config.adapters` as written, then one
entry per `adapters.registered`. Later wins on a duplicate id, which is what
`QedConfig.registered_adapters` does, and `validate.yaml` refuses the overlap
rather than letting it be decided here.

Rotation names a second variable, `..._PREVIOUS`, rather than the CLI's
`..._V2`. The CLI increments the *name* because it rewrites a file in place and
the overlap needs somewhere to live; here the names are fixed and the Secret
key each one points at is what changes.
*/}}
{{- define "qed.adapterEntries" -}}
{{- $entries := default (list) (get .Values.config "adapters") -}}
{{- range .Values.adapters.registered -}}
{{- /* An entry with no id is skipped rather than named: `validate.yaml`
       refuses it in a sentence, and which template Helm happens to render
       first should not decide whether the operator gets that sentence or a
       Go template error. */}}
{{- if .id -}}
{{- $env := include "qed.adapterSecretEnv" .id -}}
{{- $entry := dict "adapter_id" .id "secret_env" $env "kind" (default "mcp" .kind) -}}
{{- if .previousSecretKey -}}
{{- $_ := set $entry "previous_secret_env" (printf "%s_PREVIOUS" $env) -}}
{{- end -}}
{{- $entries = append $entries $entry -}}
{{- end -}}
{{- end -}}
{{- toYaml $entries -}}
{{- end -}}
