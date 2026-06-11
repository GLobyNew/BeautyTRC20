package main

import "testing"

func TestDeriveTronAddress(t *testing.T) {
	// Well-known BIP39 test mnemonic; expected address at m/44'/195'/0'/0/0
	// matches TronLink and other wallet implementations.
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	want := "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"

	got, err := deriveTronAddress(mnemonic)
	if err != nil {
		t.Fatalf("deriveTronAddress() error: %v", err)
	}
	if got != want {
		t.Errorf("deriveTronAddress() = %s, want %s", got, want)
	}
}

func TestIsBeautiful(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH", false},
		{"TUEZSdKsoDHQMeZwihtdoBiN46zxhGaaa", true},
		{"TUEZSdKsoDHQMeZwihtdoBiN46zxhGaaA", false},
		{"TUEZSdKsoDHQMeZwihtdoBiN46zxhG111", true},
		{"ab", false},
	}
	for _, tt := range tests {
		if got := isBeautiful(tt.addr); got != tt.want {
			t.Errorf("isBeautiful(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}
