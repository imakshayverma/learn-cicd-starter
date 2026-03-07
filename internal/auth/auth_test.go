package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		header      string
		wantKey     string
		wantErr     bool
		errIsNoAuth bool
	}{
		{
			name:    "returns key from valid authorization header",
			header:  "ApiKey secret-token",
			wantKey: "secret-token",
		},
		{
			name:        "returns no auth header error when header is missing",
			errIsNoAuth: true,
			wantErr:     true,
		},
		{
			name:    "returns error for wrong auth type",
			header:  "Bearer secret-token",
			wantErr: true,
		},
		{
			name:    "returns error for malformed auth header without key",
			header:  "ApiKey",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			headers := http.Header{}
			if tc.header != "" {
				headers.Set("Authorization", tc.header)
			}

			gotKey, err := GetAPIKey(headers)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if tc.errIsNoAuth && !errors.Is(err, ErrNoAuthHeaderIncluded) {
				t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
			}

			if gotKey != tc.wantKey {
				t.Fatalf("expected key %q, got %q", tc.wantKey, gotKey)
			}
		})
	}
}
