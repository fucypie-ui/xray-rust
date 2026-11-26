// Live interoperability oracle; build only against the exact pinned Go checkout.
// This file is copied alone into a disposable Go package by build-peer.sh.
package main

import (
    "context"
    "crypto/ecdh"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/hex"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "math/big"
    "net"
    "os"
    "time"

    reality "github.com/xtls/reality"
    xnet "github.com/xtls/xray-core/common/net"
    xreality "github.com/xtls/xray-core/transport/internet/reality"
)

func must(err error) { if err != nil { panic(err) } }

// Preserve net.Conn deadlines/addresses while splitting socket I/O independently
// of the TLS record lengths, to test reassembly against an unrelated engine.
type fragmented struct { net.Conn }
func (c fragmented) Read(p []byte) (int, error) {
    if len(p) > 7 { p = p[:7] }
    return c.Conn.Read(p)
}
func (c fragmented) Write(p []byte) (int, error) {
    written := 0
    for len(p) > 0 {
        n := len(p)
        if n > 11 { n = 11 }
        count, err := c.Conn.Write(p[:n])
        written += count
        p = p[count:]
        if err != nil { return written, err }
        if count == 0 { return written, io.ErrShortWrite }
    }
    return written, nil
}
func ready(listener net.Listener) {
    must(json.NewEncoder(os.Stdout).Encode(map[string]string{"address": listener.Addr().String()}))
}
func wrap(conn net.Conn, split bool) net.Conn {
    must(conn.SetDeadline(time.Now().Add(25 * time.Second)))
    if split { return fragmented{conn} }
    return conn
}
func echo(conn net.Conn) {
    defer conn.Close()
    bytes := make([]byte, 19)
    _, err := io.ReadFull(conn, bytes); must(err)
    if string(bytes) != "authenticated-vless" { panic("unexpected plaintext") }
    _, err = conn.Write([]byte("reality-auth-ok")); must(err)
}
func main() {
    if len(os.Args) < 2 { panic("usage: go-reality-peer cover|server|client [flags]") }
    mode := os.Args[1]
    flags := flag.NewFlagSet(mode, flag.ExitOnError)
    address := flags.String("address", "127.0.0.1:0", "listen or dial address")
    dest := flags.String("dest", "", "server fallback target")
    name := flags.String("name", "www.example.com", "authenticated SNI")
    sid := flags.String("short-id", "01020304", "short ID")
    split := flags.Bool("fragment", false, "split socket reads and writes")
    hybrid := flags.Bool("hybrid", false, "cover TLS server selects hybrid key exchange")
    must(flags.Parse(os.Args[2:]))
    var raw [32]byte
    for i := range raw { raw[i] = 7 }
    private, err := ecdh.X25519().NewPrivateKey(raw[:]); must(err)
    short, err := hex.DecodeString(*sid); must(err)
    if len(short) > 8 { panic("short ID too long") }
    switch mode {
    case "server":
        listener, err := net.Listen("tcp", *address); must(err)
        defer listener.Close()
        ready(listener)
        underlying, err := listener.Accept(); must(err)
        underlying = wrap(underlying, *split)
        defer underlying.Close()
        var padded [8]byte
        copy(padded[:], short)
        dialer := &net.Dialer{Timeout: 10 * time.Second}
        conn, err := reality.Server(context.Background(), underlying, &reality.Config{
            DialContext: dialer.DialContext, Type: "tcp", Dest: *dest,
            PrivateKey: private, ServerNames: map[string]bool{*name: true},
            ShortIds: map[[8]byte]bool{padded: true}, MaxTimeDiff: time.Minute,
            SessionTicketsDisabled: true,
        })
        must(err)
        if conn == nil { panic("Go REALITY server returned no authenticated connection") }
        echo(conn)
    case "client":
        raw, err := net.DialTimeout("tcp", *address, 10 * time.Second); must(err)
        raw = wrap(raw, *split)
        defer raw.Close()
        ctx, cancel := context.WithTimeout(context.Background(), 20 * time.Second)
        defer cancel()
        conn, err := xreality.UClient(raw, &xreality.Config{
            ServerName: *name, PublicKey: private.PublicKey().Bytes(), ShortId: short,
            Fingerprint: "chrome",
        }, ctx, xnet.TCPDestination(xnet.DomainAddress(*name), xnet.Port(443)))
        must(err)
        defer conn.Close()
        if verified, ok := conn.(*xreality.UConn); !ok || !verified.Verified {
            panic("Go client returned a non-REALITY connection")
        }
        _, err = conn.Write([]byte("authenticated-vless")); must(err)
        response := make([]byte, 15)
        _, err = io.ReadFull(conn, response); must(err)
        if string(response) != "reality-auth-ok" { panic("bad echo response") }
        fmt.Println("authenticated")
    case "cover":
        public, signing, err := ed25519.GenerateKey(rand.Reader); must(err)
        names := []string{*name}
        for i := 0; i < 40; i++ { names = append(names, fmt.Sprintf("cover-%d.example.com", i)) }
        template := &x509.Certificate{SerialNumber: big.NewInt(1),
            Subject: pkix.Name{CommonName: *name}, DNSNames: names,
            NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
            KeyUsage: x509.KeyUsageDigitalSignature,
            ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        }
        certificate, err := x509.CreateCertificate(rand.Reader, template, template, public, signing); must(err)
        curves := []tls.CurveID{tls.X25519}
        if *hybrid { curves = []tls.CurveID{tls.X25519MLKEM768} }
        listener, err := tls.Listen("tcp", *address, &tls.Config{
            MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
            Certificates: []tls.Certificate{{Certificate: [][]byte{certificate}, PrivateKey: signing}},
            SessionTicketsDisabled: true, CurvePreferences: curves,
        }); must(err)
        defer listener.Close()
        ready(listener)
        conn, err := listener.Accept(); must(err)
        conn = wrap(conn, *split)
        defer conn.Close()
        // Successful REALITY intercepts the target's flight, so the target sees
        // EOF before ClientFinished. Rejected authentication completes here.
        _, _ = io.Copy(io.Discard, conn)
    default:
        panic("unknown mode: " + mode)
    }
}
