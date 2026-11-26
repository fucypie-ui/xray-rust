// Independent oracle: compiled only inside the exact pinned Xray-core Go module.
// No Rust implementation or expected Rust output is consulted.
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdh"
    "crypto/ed25519"
    "crypto/hkdf"
    "crypto/hmac"
    "crypto/sha256"
    "crypto/sha512"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "math/big"
    "net"
    "os"
    "time"

    utls "github.com/refraction-networking/utls"
)

// Counter mode makes source inputs reproducible. Go may consume a variable
// amount of randomness, so the complete generated hello is frozen as an input.
type deterministicReader struct { counter uint64; pending []byte }
func (r *deterministicReader) Read(p []byte) (int, error) {
    n := len(p)
    for len(p) != 0 {
        if len(r.pending) == 0 {
            var counter [8]byte
            binary.BigEndian.PutUint64(counter[:], r.counter)
            sum := sha256.Sum256(append([]byte("xray-rs REALITY Go oracle v1"), counter[:]...))
            r.counter++
            r.pending = sum[:]
        }
        copied := copy(p, r.pending)
        p = p[copied:]
        r.pending = r.pending[copied:]
    }
    return n, nil
}
func must(err error) { if err != nil { panic(err) } }
func main() {
    random := &deterministicReader{}
    left, right := net.Pipe()
    defer left.Close()
    defer right.Close()
    conn := utls.UClient(left, &utls.Config{
        ServerName: "www.example.com", Rand: random,
        SessionTicketsDisabled: true, MinVersion: utls.VersionTLS13,
    }, utls.HelloChrome_Auto)
    must(conn.BuildHandshakeState())
    hello := conn.HandshakeState.Hello
    hello.SessionId = make([]byte, 32)
    copy(hello.Raw[39:71], hello.SessionId)
    var private [32]byte
    for i := range private { private[i] = byte(i + 1) }
    server, err := ecdh.X25519().NewPrivateKey(private[:]); must(err)
    exchange := conn.HandshakeState.State13.KeyShareKeys.Ecdhe
    if exchange == nil { exchange = conn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe }
    if exchange == nil { panic("uTLS fingerprint has no X25519 exchange") }
    shared, err := exchange.ECDH(server.PublicKey()); must(err)
    auth, err := hkdf.Key(sha256.New, shared, hello.Random[:20], "REALITY", 32); must(err)
    plaintext := make([]byte, 16)
    copy(plaintext, []byte{26, 11, 9})
    binary.BigEndian.PutUint32(plaintext[4:8], 1795723200)
    copy(plaintext[8:], []byte{1, 2, 3, 4, 0, 0, 0, 0})
    block, err := aes.NewCipher(auth); must(err)
    aead, err := cipher.NewGCM(block); must(err)
    aad := append([]byte(nil), hello.Raw...)
    session := aead.Seal(nil, hello.Random[20:], plaintext, aad)
    copy(hello.Raw[39:71], session)
    copy(hello.SessionId, session)
    record := append([]byte{22, 3, 1, byte(len(hello.Raw)>>8), byte(len(hello.Raw))}, hello.Raw...)
    var seed [32]byte
    for i := range seed { seed[i] = byte(0xa0 + i) }
    signing := ed25519.NewKeyFromSeed(seed[:])
    template := &x509.Certificate{SerialNumber: big.NewInt(0), Subject: pkix.Name{},
        NotBefore: time.Unix(1700000000, 0), NotAfter: time.Unix(1900000000, 0),
        SignatureAlgorithm: x509.PureEd25519}
    certificate, err := x509.CreateCertificate(random, template, template, signing.Public(), signing); must(err)
    tag := hmac.New(sha512.New, auth)
    tag.Write(signing.Public().(ed25519.PublicKey))
    copy(certificate[len(certificate)-64:], tag.Sum(nil))
    out := map[string]any{
        "schema": 1, "go_reference": "67756b3674d56b72c7a7e675e8dcd3f883e1b2f7",
        "reality_dependency": "4bb46b2afd8b", "timestamp": uint64(1795723200),
        "server_name": hello.ServerName, "short_id": "01020304",
        "server_private_key": hex.EncodeToString(private[:]),
        "server_public_key": hex.EncodeToString(server.PublicKey().Bytes()),
        "client_public_key": hex.EncodeToString(exchange.PublicKey().Bytes()),
        "client_random": hex.EncodeToString(hello.Random),
        "shared_secret": hex.EncodeToString(shared), "auth_key": hex.EncodeToString(auth),
        "plaintext": hex.EncodeToString(plaintext), "aad": hex.EncodeToString(aad),
        "session_id": hex.EncodeToString(session), "client_hello_record": hex.EncodeToString(record),
        "ed25519_public_key": hex.EncodeToString(signing.Public().(ed25519.PublicKey)),
        "certificate": hex.EncodeToString(certificate), "certificate_hmac": hex.EncodeToString(tag.Sum(nil)),
    }
    encoder := json.NewEncoder(os.Stdout)
    encoder.SetIndent("", "  ")
    must(encoder.Encode(out))
}
