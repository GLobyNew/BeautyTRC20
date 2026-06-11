# BeautyTRC20

Generator of beautiful TRC20 (TRON) addresses.

Brute-forces random BIP39 mnemonics until the derived TRON address
(derivation path `m/44'/195'/0'/0/0`) ends with N identical characters,
e.g. `T...xxxxx55555`.

## Install

Requires Go 1.26+.

```sh
go build
```

## Usage

```sh
./BeautyTRC20 -n <count>
```

| Flag | Description |
|------|-------------|
| `-n` | Number of identical characters the address must end with (1–33, required) |

Example:

```sh
./BeautyTRC20 -n 5
```

The search runs on all CPU cores and prints progress once per second.
When a match is found, the mnemonic and address are printed and saved
to `success.txt`.

Each extra character makes the search roughly 58× slower (base58
alphabet), so values above 5–6 can take a very long time.

## Output

```
Searching for a TRON address ending in 5 identical characters (16 workers)...
Found after 8456193 attempts in 4m12.301s
Address:  TXk3...Vqqqqq
Mnemonic: word1 word2 ... word12
Saved to success.txt
```

⚠️ `success.txt` contains the mnemonic (private key). Keep it secret.

## Test

```sh
go test ./...
```

## License

See [LICENSE](LICENSE).
