package main

import (
	"errors"
	"os"
)

type FileReader interface {
	// getFileContent reads the content of a file and returns it as a string
	getFileContent(path string) (string, error)
}

type fileReaderImpl struct {
}

func NewFileReader() FileReader {
	return &fileReaderImpl{}
}

func (f *fileReaderImpl) getFileContent(path string) (string, error) {

	if path == "" {
		return "", errors.New("path is empty")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "", err
	}

	content, err := os.ReadFile(path)

	if err != nil {
		return "", err
	}

	return string(content), nil
}

type mockFileReader struct {
	pathContent map[string]string
}

func NewMockFileReader() *mockFileReader {
	return &mockFileReader{
		pathContent: make(map[string]string),
	}
}

func (m *mockFileReader) getFileContent(path string) (string, error) {
	content, ok := m.pathContent[path]

	if !ok {
		return "", os.ErrNotExist
	}

	return content, nil
}

func (m *mockFileReader) setFileContent(path, content string) {
	m.pathContent[path] = content
}
