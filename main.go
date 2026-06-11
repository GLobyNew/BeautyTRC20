package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/sha3"
)

const outputFile = "success.txt"

// deriveTronAddress derives the TRON address for a BIP39 mnemonic at the
// standard TRON derivation path m/44'/195'/0'/0/0.
func deriveTronAddress(mnemonic string) (string, error) {
	seed := bip39.NewSeed(mnemonic, "")
	key, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", err
	}
	path := []uint32{
		hdkeychain.HardenedKeyStart + 44,
		hdkeychain.HardenedKeyStart + 195,
		hdkeychain.HardenedKeyStart + 0,
		0,
		0,
	}
	for _, idx := range path {
		if key, err = key.Derive(idx); err != nil {
			return "", err
		}
	}
	priv, err := key.ECPrivKey()
	if err != nil {
		return "", err
	}
	// TRON address = 0x41 + last 20 bytes of Keccak-256 of the uncompressed
	// public key (without the 0x04 prefix), base58check-encoded.
	pub := priv.PubKey().SerializeUncompressed()
	h := sha3.NewLegacyKeccak256()
	h.Write(pub[1:])
	digest := h.Sum(nil)
	return base58.CheckEncode(digest[12:], 0x41), nil
}

// isBeautiful reports whether the last 3 characters of addr are identical.
func isBeautiful(addr string) bool {
	n := len(addr)
	if n < 3 {
		return false
	}
	return addr[n-1] == addr[n-2] && addr[n-2] == addr[n-3]
}

type result struct {
	mnemonic string
	address  string
}

func worker(ctx context.Context, attempts *atomic.Uint64, found chan<- result) {
	for ctx.Err() == nil {
		entropy, err := bip39.NewEntropy(128)
		if err != nil {
			continue
		}
		mnemonic, err := bip39.NewMnemonic(entropy)
		if err != nil {
			continue
		}
		addr, err := deriveTronAddress(mnemonic)
		if err != nil {
			// Invalid child keys are astronomically rare; just try again.
			continue
		}
		attempts.Add(1)
		if isBeautiful(addr) {
			select {
			case found <- result{mnemonic: mnemonic, address: addr}:
			default:
			}
			return
		}
	}
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var attempts atomic.Uint64
	found := make(chan result, 1)

	workers := runtime.NumCPU()
	fmt.Printf("Searching for a TRON address ending in 3 identical characters (%d workers)...\n", workers)
	for range workers {
		go worker(ctx, &attempts, found)
	}

	start := time.Now()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case r := <-found:
			cancel()
			fmt.Printf("\rFound after %d attempts in %s\n", attempts.Load(), time.Since(start).Round(time.Millisecond))
			fmt.Println("Address: ", r.address)
			fmt.Println("Mnemonic:", r.mnemonic)
			content := fmt.Sprintf("mnemonic: %s\naddress: %s\n", r.mnemonic, r.address)
			if err := os.WriteFile(outputFile, []byte(content), 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", outputFile, err)
				os.Exit(1)
			}
			fmt.Println("Saved to", outputFile)
			return
		case <-ticker.C:
			n := attempts.Load()
			fmt.Printf("\rattempts: %d (%.0f/s)", n, float64(n)/time.Since(start).Seconds())
		}
	}
}
