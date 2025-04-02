package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_ValidHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey test-api-key-123")

	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if key != "test-api-key-123" {
		t.Errorf("Expected key 'test-api-key-123', got '%s'", key)
	}
}

func TestGetAPIKey_NoHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("Expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	testCases := []struct {
		name   string
		header string
	}{
		{"Empty after ApiKey", "ApiKey "},
		{"No ApiKey prefix", "Bearer token"},
		{"No space", "ApiKey"},
		{"Multiple spaces", "ApiKey  extra  parts"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set("Authorization", tc.header)

			_, err := GetAPIKey(headers)
			if err == nil {
				t.Error("Expected error for malformed header, got nil")
			}
		})
	}
}
