package main

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/template"

	"github.com/dgraph-io/ristretto"
	"github.com/rs/xid"
)

type ErrorHandler struct {
	defaultContentType string
	pagesRoot          string
	contentCache       *ristretto.Cache
	fileReader         FileReader
}

func NewErrorHandler(
	defaultContentType string,
	pagesRoot string,
	fileReader FileReader,
	cacheMaxMemBytes int64) *ErrorHandler {

	cache, _ := ristretto.NewCache(&ristretto.Config{
		MaxCost:     cacheMaxMemBytes,
		NumCounters: 1e7,
		BufferItems: 64,
	})

	return &ErrorHandler{
		defaultContentType: defaultContentType,
		pagesRoot:          pagesRoot,
		fileReader:         fileReader,
		contentCache:       cache,
	}
}

func (e *ErrorHandler) getKey(code int, contentType string) string {
	return fmt.Sprintf("%d-%s", code, contentType)
}

func (e *ErrorHandler) getExtensions(contentType string) ([]string, error) {

	cext, err := mime.ExtensionsByType(contentType)

	if err != nil {
		logger.Info().
			Err(err).
			Str("content_type", contentType).
			Msg("Unexpected error while getting extension by content type")
		return nil, err
	}

	if len(cext) == 0 {
		logger.Info().
			Str("content_type", contentType).
			Msg("No extension found for content type")
		return nil, errors.New("no extension found for content type")
	}

	for i, ext := range cext {
		cext[i] = strings.TrimPrefix(ext, ".")
	}

	return cext, nil
}

func (e *ErrorHandler) getPossibleFiles(code int, exts []string) []string {

	fileNames := make([]string, 0, len(exts)*8)

	for _, ext := range exts {
		fileNames = append(fileNames,
			fmt.Sprintf("%s/%d.%s", e.pagesRoot, code, ext),
			fmt.Sprintf("%s/%d.%s.tpl", e.pagesRoot, code, ext),
			fmt.Sprintf("%s/%dx.%s", e.pagesRoot, code/10, ext),
			fmt.Sprintf("%s/%dx.%s.tpl", e.pagesRoot, code/10, ext),
			fmt.Sprintf("%s/%dxx.%s", e.pagesRoot, code/100, ext),
			fmt.Sprintf("%s/%dxx.%s.tpl", e.pagesRoot, code/100, ext),
			fmt.Sprintf("%s/all.%s", e.pagesRoot, ext),
			fmt.Sprintf("%s/all.%s.tpl", e.pagesRoot, ext),
		)
	}

	return fileNames
}

func (e *ErrorHandler) createDefaultContent(intCode int, contentType string, statusText string) string {
	switch contentType {
	case "text/html":
		return fmt.Sprintf("<html><head><title>%d %s</title></head><body style='text-align:center;'><h1>%d</h1><h2>%s</h2></body></html>", intCode, statusText, intCode, statusText)
	case "text/plain":
		return fmt.Sprintf("%d: %s", intCode, statusText)
	case "application/json":
		return fmt.Sprintf("{\"code\":%d,\"text\":\"%s\"}", intCode, statusText)
	case "application/xml":
		return fmt.Sprintf("<error><code>%d</code><text>%s</text></error>", intCode, statusText)
	default:
		return ""
	}
}

func (e *ErrorHandler) getContent(code int, contentType string, text string) string {

	key := e.getKey(code, contentType)

	cachedContent, ok := e.contentCache.Get(key)

	if ok {
		return cachedContent.(string)
	}

	exts, err := e.getExtensions(contentType)

	if err != nil {
		return ""
	}

	files := e.getPossibleFiles(code, exts)

	var file string
	var content string

	for _, file = range files {
		content, err = e.fileReader.getFileContent(file)

		if err != nil {
			if !os.IsNotExist(err) {
				logger.Error().
					Err(err).
					Str("file", file).
					Msg("Failed to read file")
				return ""
			}
		} else {
			break
		}
	}

	if content == "" {
		logger.Info().
			Int("status_code", code).
			Str("content_type", contentType).
			Msg("No content found")

		content = e.createDefaultContent(code, contentType, text)
		e.contentCache.Set(key, content, int64(len(key)+len(content)))
		return content
	}

	if !strings.HasSuffix(file, ".tpl") {
		e.contentCache.Set(key, content, int64(len(key)+len(content)))
		return content
	}

	tpl, err := template.New("tpl").Parse(content)

	if err != nil {
		logger.Info().
			Err(err).
			Str("file", file).
			Msg("Failed to parse template")
	}

	var tplContent strings.Builder

	err = tpl.Execute(&tplContent, map[string]interface{}{
		"code": code,
		"text": text,
	})

	if err != nil {
		logger.Info().
			Err(err).
			Str("file", file).
			Int("status_code", code).
			Msg("Failed to execute template")
	}

	content = tplContent.String()

	e.contentCache.Set(key, content, int64(len(key)+len(content)))

	return content
}

func (e *ErrorHandler) HandleError(w http.ResponseWriter, r *http.Request) {

	intCode := http.StatusNotFound
	statusText := http.StatusText(intCode)

	if codeHeader := r.Header.Get(CodeHeader); codeHeader != "" {
		var err error
		intCode, err = strconv.Atoi(codeHeader)
		if err != nil {
			logger.Warn().
				Err(err).
				Str("code", codeHeader).
				Msg("Invalid status code, defaulting to 404")
			intCode = http.StatusNotFound
		}
		statusText = http.StatusText(intCode)

		if statusText == "" {
			if intCode == 497 {
				statusText = "HTTP Request Sent to HTTPS Port"
			} else {
				statusText = fmt.Sprintf("Request failed with code %d", intCode)
			}
		}
	} else {
		logger.Warn().Msgf("Header %s not provided, defaulting to 404", CodeHeader)
	}

	requestId := r.Header.Get(RequestIdHeader)
	if requestId == "" {
		requestId = xid.New().String()
	}

	logger.Info().
		Str("request_id", requestId).
		Str("method", r.Method).
		Str("path", r.URL.Path).
		Str("proto", r.Proto).
		Int("status_code", intCode).
		Str("status_text", statusText).
		Msg("Request received")

	// get the content type or default to text/html
	contentType := r.Header.Get(ContentTypeHeader)

	if contentType == "" {
		contentType = e.defaultContentType
	}

	content := e.getContent(intCode, contentType, statusText)

	if content == "" {
		contentType = e.defaultContentType
		content = e.getContent(intCode, e.defaultContentType, statusText)

		if content == "" {
			contentType = "text/html"
			content = e.getContent(intCode, e.defaultContentType, statusText)
		}
	}

	w.Header().Set(ContentTypeHeader, contentType)
	w.Header().Set(RequestIdHeader, requestId)
	w.WriteHeader(intCode)
	w.Write([]byte(content))
}
