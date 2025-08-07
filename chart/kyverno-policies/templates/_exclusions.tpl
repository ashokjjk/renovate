{{- define "exclusions" }}
{{- if .exclusions }}
{{- $any := (list) }}
{{- range $key, $value := .exclusions }}
  {{- if $value.match }}
    {{- if $value.match.all }}
      {{- fail "match.all is not supported" }}
    {{- end }}
    {{- if $value.match.any }}
      {{- $any = concat $any $value.match.any }}
    {{- end }}
  {{- end }}
{{- end }}
{{- if $any -}}
exclude:
  any: {{ $any | toYaml | nindent 4 }}
{{- end }}
{{- end }}
{{- end }}
