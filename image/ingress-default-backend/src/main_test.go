package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestDefaultCode(t *testing.T) {

	req, err := http.NewRequest("GET", "/", nil)

	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "text/plain")

	errorHandler = NewErrorHandler("text/plain", "/var/www", NewMockFileReader(), 10*1024*1024)

	recorder := httptest.NewRecorder()
	handler := http.HandlerFunc(errorHandler.HandleError)

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNotFound {
		t.Errorf("Expected status code %d, but got %d", http.StatusNoContent, recorder.Code)
	}
}

func TestDefaultContentType(t *testing.T) {

	req, err := http.NewRequest("GET", "/", nil)

	if err != nil {
		t.Fatal(err)
	}

	status := http.StatusBadRequest

	req.Header.Set("X-Code", strconv.Itoa(status))

	errorHandler = NewErrorHandler("text/html", "/var/www", NewMockFileReader(), 10*1024*1024)

	recorder := httptest.NewRecorder()
	handler := http.HandlerFunc(errorHandler.HandleError)

	handler.ServeHTTP(recorder, req)

	if recorder.Code != status {
		t.Errorf("Expected status code %d, but got %d", http.StatusNoContent, recorder.Code)
	}

	if recorder.Header().Get("Content-Type") != "text/html" {
		t.Errorf("Expected Content-Type %s, but got %s", "text/html", recorder.Header().Get("Content-Type"))
	}

	// body contains the code and its text
	statusText := http.StatusText(status)
	body := recorder.Body.String()

	if !strings.Contains(body, strconv.Itoa(status)) || !strings.Contains(body, statusText) {
		t.Errorf("Expected body to contain status code and text, but got %s", body)
	}
}

func TestExistingCustomContentType(t *testing.T) {

	req, err := http.NewRequest("GET", "/", nil)

	if err != nil {
		t.Fatal(err)
	}

	status := http.StatusBadRequest

	fileReader := NewMockFileReader()
	errorHandler = NewErrorHandler("text/plain", "/var/www", fileReader, 10*1024*1024)

	fileReader.setFileContent("/var/www/400.html", "<h1>Bad Request</h1>")

	tp := "text/html"
	req.Header.Set("Content-Type", tp)
	req.Header.Set("X-Code", strconv.Itoa(status))

	recorder := httptest.NewRecorder()
	handler := http.HandlerFunc(errorHandler.HandleError)

	handler.ServeHTTP(recorder, req)

	if recorder.Code != status {
		t.Errorf("Expected status code %d, but got %d", http.StatusNoContent, recorder.Code)
	}

	if recorder.Header().Get("Content-Type") != tp {
		t.Errorf("Expected Content-Type %s, but got %s", tp, recorder.Header().Get("Content-Type"))
	}

	if recorder.Body.String() != "<h1>Bad Request</h1>" {
		t.Errorf("Expected body %s, but got %s", "<h1>Bad Request</h1>", recorder.Body.String())
	}
}

func TestGenericSingleDigitCustomContentType(t *testing.T) {

	req, err := http.NewRequest("GET", "/", nil)

	if err != nil {
		t.Fatal(err)
	}

	status := http.StatusBadRequest

	fileReader := NewMockFileReader()
	errorHandler = NewErrorHandler("text/plain", "/var/www", fileReader, 10*1024*1024)

	fileReader.setFileContent("/var/www/40x.html", "<h1>Bad Request</h1>")

	tp := "text/html"
	req.Header.Set("Content-Type", tp)
	req.Header.Set("X-Code", strconv.Itoa(status))

	recorder := httptest.NewRecorder()
	handler := http.HandlerFunc(errorHandler.HandleError)

	handler.ServeHTTP(recorder, req)

	if recorder.Code != status {
		t.Errorf("Expected status code %d, but got %d", http.StatusNoContent, recorder.Code)
	}

	if recorder.Header().Get("Content-Type") != tp {
		t.Errorf("Expected Content-Type %s, but got %s", tp, recorder.Header().Get("Content-Type"))
	}

	if recorder.Body.String() != "<h1>Bad Request</h1>" {
		t.Errorf("Expected body %s, but got %s", "<h1>Bad Request</h1>", recorder.Body.String())
	}
}

func TestGenericTwoDigitCustomContentType(t *testing.T) {

	req, err := http.NewRequest("GET", "/", nil)

	if err != nil {
		t.Fatal(err)
	}

	status := http.StatusBadRequest

	fileReader := NewMockFileReader()
	errorHandler = NewErrorHandler("text/plain", "/var/www", fileReader, 10*1024*1024)

	fileReader.setFileContent("/var/www/4xx.html", "<h1>Bad Request</h1>")

	tp := "text/html"
	req.Header.Set("Content-Type", tp)
	req.Header.Set("X-Code", strconv.Itoa(status))

	recorder := httptest.NewRecorder()
	handler := http.HandlerFunc(errorHandler.HandleError)

	handler.ServeHTTP(recorder, req)

	if recorder.Code != status {
		t.Errorf("Expected status code %d, but got %d", http.StatusNoContent, recorder.Code)
	}

	if recorder.Header().Get("Content-Type") != tp {
		t.Errorf("Expected Content-Type %s, but got %s", tp, recorder.Header().Get("Content-Type"))
	}

	if recorder.Body.String() != "<h1>Bad Request</h1>" {
		t.Errorf("Expected body %s, but got %s", "<h1>Bad Request</h1>", recorder.Body.String())
	}
}

func TestGenericAllCustomContentType(t *testing.T) {

	req, err := http.NewRequest("GET", "/", nil)

	if err != nil {
		t.Fatal(err)
	}

	status := http.StatusBadRequest

	fileReader := NewMockFileReader()
	errorHandler = NewErrorHandler("text/plain", "/var/www", fileReader, 10*1024*1024)

	fileReader.setFileContent("/var/www/all.html", "<h1>Bad Request</h1>")

	tp := "text/html"
	req.Header.Set("Content-Type", tp)
	req.Header.Set("X-Code", strconv.Itoa(status))

	recorder := httptest.NewRecorder()
	handler := http.HandlerFunc(errorHandler.HandleError)

	handler.ServeHTTP(recorder, req)

	if recorder.Code != status {
		t.Errorf("Expected status code %d, but got %d", http.StatusNoContent, recorder.Code)
	}

	if recorder.Header().Get("Content-Type") != tp {
		t.Errorf("Expected Content-Type %s, but got %s", tp, recorder.Header().Get("Content-Type"))
	}

	if recorder.Body.String() != "<h1>Bad Request</h1>" {
		t.Errorf("Expected body %s, but got %s", "<h1>Bad Request</h1>", recorder.Body.String())
	}
}

func TestJsonContentType(t *testing.T) {

	req, err := http.NewRequest("GET", "/", nil)

	if err != nil {
		t.Fatal(err)
	}

	status := http.StatusBadRequest

	fileReader := NewMockFileReader()
	errorHandler = NewErrorHandler("text/plain", "/var/www", fileReader, 10*1024*1024)

	fileReader.setFileContent("/var/www/400.json", "{\"error\": \"Bad Request\"}")

	tp := "application/json"
	req.Header.Set("Content-Type", tp)
	req.Header.Set("X-Code", strconv.Itoa(status))

	recorder := httptest.NewRecorder()
	handler := http.HandlerFunc(errorHandler.HandleError)

	handler.ServeHTTP(recorder, req)

	if recorder.Code != status {
		t.Errorf("Expected status code %d, but got %d", http.StatusNoContent, recorder.Code)
	}

	if recorder.Header().Get("Content-Type") != tp {
		t.Errorf("Expected Content-Type %s, but got %s", tp, recorder.Header().Get("Content-Type"))
	}

	if recorder.Body.String() != "{\"error\": \"Bad Request\"}" {
		t.Errorf("Expected body %s, but got %s", "{\"error\": \"Bad Request\"}", recorder.Body.String())
	}
}

func TestNoContentType(t *testing.T) {

	req, err := http.NewRequest("GET", "/", nil)

	if err != nil {
		t.Fatal(err)
	}

	status := http.StatusBadRequest

	fileReader := NewMockFileReader()
	errorHandler = NewErrorHandler("text/plain", "/var/www", fileReader, 10*1024*1024)

	fileReader.setFileContent("/var/www/400.html", "<h1>Bad Request</h1>")
	fileReader.setFileContent("/var/www/400.txt", "Bad Request")

	req.Header.Set("X-Code", strconv.Itoa(status))

	recorder := httptest.NewRecorder()
	handler := http.HandlerFunc(errorHandler.HandleError)

	handler.ServeHTTP(recorder, req)

	if recorder.Code != status {
		t.Errorf("Expected status code %d, but got %d", http.StatusNoContent, recorder.Code)
	}

	if recorder.Header().Get("Content-Type") != "text/plain" {
		t.Errorf("Expected Content-Type %s, but got %s", "text/plain", recorder.Header().Get("Content-Type"))
	}

	if recorder.Body.String() != "Bad Request" {
		t.Errorf("Expected body %s, but got %s", "Bad Request", recorder.Body.String())
	}
}

func TestTemplatedCustom(t *testing.T) {

	req, err := http.NewRequest("GET", "/", nil)

	if err != nil {
		t.Fatal(err)
	}

	status := http.StatusBadRequest

	fileReader := NewMockFileReader()
	errorHandler = NewErrorHandler("text/plain", "/var/www", fileReader, 10*1024*1024)

	fileReader.setFileContent("/var/www/40x.html.tpl", "<h1>{{.text}} {{.code}}</h1>")

	tp := "text/html"
	req.Header.Set("Content-Type", tp)
	req.Header.Set("X-Code", strconv.Itoa(status))

	recorder := httptest.NewRecorder()
	handler := http.HandlerFunc(errorHandler.HandleError)

	handler.ServeHTTP(recorder, req)

	if recorder.Code != status {
		t.Errorf("Expected status code %d, but got %d", http.StatusNoContent, recorder.Code)
	}

	if recorder.Header().Get("Content-Type") != tp {
		t.Errorf("Expected Content-Type %s, but got %s", tp, recorder.Header().Get("Content-Type"))
	}

	if recorder.Body.String() != "<h1>Bad Request 400</h1>" {
		t.Errorf("Expected body %s, but got %s", "<h1>Bad Request 400</h1>", recorder.Body.String())
	}
}

func TestDefaultJsonContentType(t *testing.T) {

	req, err := http.NewRequest("GET", "/", nil)

	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Code", strconv.Itoa(http.StatusBadRequest))

	errorHandler = NewErrorHandler("text/html", "/var/www", NewMockFileReader(), 10*1024*1024)

	recorder := httptest.NewRecorder()
	handler := http.HandlerFunc(errorHandler.HandleError)

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d, but got %d", http.StatusBadRequest, recorder.Code)
	}

	if recorder.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type %s, but got %s", "application/json", recorder.Header().Get("Content-Type"))
	}

	expected := "{\"code\":400,\"text\":\"Bad Request\"}"

	if recorder.Body.String() != expected {
		t.Errorf("Expected body %s, but got %s", expected, recorder.Body.String())
	}
}

func TestDefaultPlainTextContentType(t *testing.T) {

	req, err := http.NewRequest("GET", "/", nil)

	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Code", strconv.Itoa(http.StatusBadRequest))

	errorHandler = NewErrorHandler("text/html", "/var/www", NewMockFileReader(), 10*1024*1024)

	recorder := httptest.NewRecorder()
	handler := http.HandlerFunc(errorHandler.HandleError)

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d, but got %d", http.StatusBadRequest, recorder.Code)
	}

	if recorder.Header().Get("Content-Type") != "text/plain" {
		t.Errorf("Expected Content-Type %s, but got %s", "text/plain", recorder.Header().Get("Content-Type"))
	}

	expected := "400: Bad Request"

	if recorder.Body.String() != expected {
		t.Errorf("Expected body %s, but got %s", expected, recorder.Body.String())
	}
}

func TestDefaultXmlContentType(t *testing.T) {

	req, err := http.NewRequest("GET", "/", nil)

	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("X-Code", strconv.Itoa(http.StatusBadRequest))

	errorHandler = NewErrorHandler("text/html", "/var/www", NewMockFileReader(), 10*1024*1024)

	recorder := httptest.NewRecorder()
	handler := http.HandlerFunc(errorHandler.HandleError)

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d, but got %d", http.StatusBadRequest, recorder.Code)
	}

	if recorder.Header().Get("Content-Type") != "application/xml" {
		t.Errorf("Expected Content-Type %s, but got %s", "application/xml", recorder.Header().Get("Content-Type"))
	}

	expected := "<error><code>400</code><text>Bad Request</text></error>"

	if recorder.Body.String() != expected {
		t.Errorf("Expected body %s, but got %s", expected, recorder.Body.String())
	}
}
