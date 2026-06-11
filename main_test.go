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
		addr    string
		tailLen int
		want    bool
	}{
		{"TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH", 3, false},
		{"TUEZSdKsoDHQMeZwihtdoBiN46zxhGWaaa", 3, true},
		{"TUEZSdKsoDHQMeZwihtdoBiN46zxhGWaaa", 4, false},
		{"TUEZSdKsoDHQMeZwihtdoBiN46zxhaaaaa", 5, true},
		{"TUEZSdKsoDHQMeZwihtdoBiN46zxhAaaaa", 5, false},
		{"TUEZSdKsoDHQMeZwihtdoBiN46zxh11111", 5, true},
		{"ab", 3, false},
	}
	for _, tt := range tests {
		if got := isBeautiful(tt.addr, tt.tailLen); got != tt.want {
			t.Errorf("isBeautiful(%q, %d) = %v, want %v", tt.addr, tt.tailLen, got, tt.want)
		}
	}
}
