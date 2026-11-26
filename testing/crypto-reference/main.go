// Run from the authoritative Xray-core module:
// go run ../xray-rs/testing/crypto-reference/main.go > ../xray-rs/testing/crypto-reference/vectors.json
// Uses Go crypto and Xray's BLAKE3 independently of the Rust code under test.
package main

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"

	"lukechampine.com/blake3"
)

type mlkemVector struct {
	Name   string `json:"name"`
	Seed   string `json:"seed"`
	Client string `json:"client"`
	Hash32 string `json:"hash32"`
}

type curveVector struct {
	Name       string `json:"name"`
	Input      string `json:"input"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	Hash32     string `json:"hash32"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	encode := base64.RawURLEncoding.EncodeToString
	fixtures := struct {
		Reference string        `json:"reference"`
		MLKEM768  []mlkemVector `json:"mlkem768"`
		X25519    []curveVector `json:"x25519"`
	}{Reference: "Xray-core 67756b3674d56b72c7a7e675e8dcd3f883e1b2f7"}
	for _, name := range []string{"zero", "ones", "ascending", "descending", "ascending-d-zero-z"} {
		var seed [64]byte
		for i := range seed {
			switch name {
			case "ones":
				seed[i] = 255
			case "ascending":
				seed[i] = byte(i)
			case "descending":
				seed[i] = byte(255 - i)
			case "ascending-d-zero-z":
				if i < 32 {
					seed[i] = byte(i)
				}
			}
		}
		key, err := mlkem.NewDecapsulationKey768(seed[:])
		must(err)
		client := key.EncapsulationKey().Bytes()
		hash := blake3.Sum256(client)
		fixtures.MLKEM768 = append(fixtures.MLKEM768, mlkemVector{name, encode(seed[:]), encode(client), encode(hash[:])})
	}
	for _, name := range []string{"zero", "ones", "ascending", "descending", "rfc7748-alice"} {
		input := make([]byte, 32)
		for i := range input {
			switch name {
			case "ones":
				input[i] = 255
			case "ascending":
				input[i] = byte(i)
			case "descending":
				input[i] = byte(255 - i)
			}
		}
		if name == "rfc7748-alice" {
			var err error
			input, err = hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
			must(err)
		}
		private := append([]byte(nil), input...)
		private[0] &= 248
		private[31] &= 127
		private[31] |= 64
		key, err := ecdh.X25519().NewPrivateKey(private)
		must(err)
		public := key.PublicKey().Bytes()
		hash := blake3.Sum256(public)
		fixtures.X25519 = append(fixtures.X25519, curveVector{name, encode(input), encode(private), encode(public), encode(hash[:])})
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	must(encoder.Encode(fixtures))
}
