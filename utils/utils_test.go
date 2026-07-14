// STATUS: DIAMANT VGT SUPREME
//go:build linux

package utils

import (
	"testing"
)

func TestSanitizeStr(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal_text", "normal_text"},
		{"hello\x1b[31mred\x1b[0mworld", "hello31mred0mworld"},
		{"user; rm -rf /", "user rm -rf /"},
		{"cat /etc/passwd\x00\x07", "cat /etc/passwd"},
		{"1234567890123456789012345678901234567890123456789012345678901234567890", "1234567890123456789012345678901234567890123456789012345678901234"},
	}

	for _, tt := range tests {
		res := SanitizeStr(tt.input)
		if res != tt.expected {
			t.Errorf("SanitizeStr(%q) = %q, expected %q", tt.input, res, tt.expected)
		}
	}
}

func TestSanitizeIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.1", "192.168.1.1"},
		{" 10.0.0.1 ", "10.0.0.1"},
		{"::1", "::1"},
		{"2001:db8::68", "2001:db8::68"},
		{"invalid_ip_address", "UNKNOWN_HOST"},
		{"192.168.1.1; rm -rf /", "UNKNOWN_HOST"},
	}

	for _, tt := range tests {
		res := SanitizeIP(tt.input)
		if res != tt.expected {
			t.Errorf("SanitizeIP(%q) = %q, expected %q", tt.input, res, tt.expected)
		}
	}
}

func TestFastParseUint(t *testing.T) {
	tests := []struct {
		input    string
		expected uint64
	}{
		{"MemTotal:       32800000 kB", 32800000},
		{"12345", 12345},
		{"0", 0},
		{"abc99xyz", 99},
	}

	for _, tt := range tests {
		res := FastParseUint(tt.input)
		if res != tt.expected {
			t.Errorf("FastParseUint(%q) = %d, expected %d", tt.input, res, tt.expected)
		}
	}
}

func TestB2s(t *testing.T) {
	input := []int8{'L', 'i', 'n', 'u', 'x', 0, 't', 'r', 'a', 's', 'h'}
	res := B2s(input)
	if res != "Linux" {
		t.Errorf("B2s() = %q, expected %q", res, "Linux")
	}
}
