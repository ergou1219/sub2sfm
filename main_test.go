package main

import (
	"os"
	"testing"
)

func TestGetEnv(t *testing.T) {
	key := "TEST_SUB2SFM_ENV"
	if got := getEnv(key, "default_val"); got != "default_val" {
		t.Fatalf("expected fallback 'default_val', got %q", got)
	}

	os.Setenv(key, "custom_val")
	defer os.Unsetenv(key)

	if got := getEnv(key, "default_val"); got != "custom_val" {
		t.Fatalf("expected 'custom_val', got %q", got)
	}
}
