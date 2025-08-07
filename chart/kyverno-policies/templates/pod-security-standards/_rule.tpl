
{{- define "pod-security-rule" }}
{{- if .enabled }}
---
{{- $name := index .policyKeys .controlName }}
{{- $namedFilters := index .exclusions $name }}
{{- $filters := dict "exclude" (dict "any" (list)) "images" (list) }}
{{- if $namedFilters }}
{{- range $key, $value := $namedFilters }}
  {{- if $value.match }}
    {{- if $value.match.all }}
      {{- fail "match.all is not supported" }}
    {{- end }}
    {{- if $value.match.any }}
      {{- $_ := set ($filters.exclude) "any" (concat $filters.exclude.any $value.match.any) }}
    {{- end }}
  {{- end }}
  {{- if $value.images }}
    {{- $_ := set $filters "images" (concat $filters.images $value.images) }}
  {{- end }} 
{{- end }}
{{- end }}
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: pss-{{ $name }}
spec:
  validationFailureAction: {{ .validationFailureAction }}
  failurePolicy: {{ .failurePolicy }}
  admission: {{ .admission }}
  background: {{ .background }}
  rules:
    - name: {{ $name }}
      match:
        any:
        - resources:
            kinds:
            - Pod
      {{- if $filters.exclude.any }}
      exclude:
        any: {{ $filters.exclude.any | toYaml | nindent 10 }}
      {{- end}}
      validate:
        allowExistingViolations: true
        podSecurity:
          {{- $pss := . }}
          level: {{ $pss.level | default "baseline" }}
          version: {{ $pss.version | default "latest" }}
          exclude:
          {{- range $pss.controls }}
            {{- if ne . $pss.controlName }}
            - controlName: {{ . }}
              {{- if not (has . $pss.podLevelControls) }}
              images: ["*"]
              {{- end }}
            {{- else }}
              {{- if $filters.images }}
            - controlName: {{ . }}
              images: {{ $filters.images | toYaml | nindent 14 }}
              {{- end }}
            {{- end }}
          {{- end }}
{{- end}}
{{- end}}
