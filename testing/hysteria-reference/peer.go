// Independent live peer using the pinned Go fork's QUIC/H3 and proxy codecs.
// Built only in a disposable git-archive checkout by build-peer.sh.
package main

import (
    "bytes"
    "context"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "io"
    "math/big"
    "net/http"
    "os"
    "sync/atomic"
    "time"

    "github.com/apernet/quic-go"
    "github.com/apernet/quic-go/http3"
    "github.com/apernet/quic-go/quicvarint"
    proxy "github.com/xtls/xray-core/proxy/hysteria"
)

var mode = flag.String("mode", "server", "server or client")
var address = flag.String("address", "127.0.0.1:0", "QUIC listen or remote address")
var auth = flag.String("auth", "secret", "Hysteria password")
var rootDER = flag.String("root-der", "", "trusted server DER in hex; required for client")
var omitDatagram = flag.Bool("omit-datagram", true, "match Xray's client transport parameter omission")

func main() {
    flag.Parse()
    ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
    defer cancel()
    var err error
    switch *mode { case "server": err = server(ctx); case "client": err = client(ctx); default: err = errors.New("unknown mode") }
    if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}
func config() *quic.Config {
    return &quic.Config{EnableDatagrams: true, MaxDatagramFrameSize: 1200,
        MaxIdleTimeout: 15*time.Second, KeepAlivePeriod: time.Second, DisablePathMTUDiscovery: true}
}
func certificate() (tls.Certificate, []byte, error) {
    key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); if err != nil { return tls.Certificate{}, nil, err }
    template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName:"localhost"}, DNSNames:[]string{"localhost"},
        NotBefore:time.Now().Add(-time.Minute), NotAfter:time.Now().Add(time.Hour),
        KeyUsage:x509.KeyUsageDigitalSignature, ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid:true}
    der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
    return tls.Certificate{Certificate:[][]byte{der}, PrivateKey:key}, der, err
}
func server(ctx context.Context) error {
    cert, der, err := certificate(); if err != nil { return err }
    cfg := config(); cfg.AssumePeerMaxDatagramFrameSize = 1200
    listener, err := quic.ListenAddr(*address, &tls.Config{Certificates:[]tls.Certificate{cert}, NextProtos:[]string{"h3"}, MinVersion:tls.VersionTLS13}, cfg)
    if err != nil { return err }; defer listener.Close()
    if err = json.NewEncoder(os.Stdout).Encode(map[string]string{"address":listener.Addr().String(), "certificate_der":hex.EncodeToString(der)}); err != nil { return err }
    for { conn, err := listener.Accept(ctx); if err != nil { return err }; go serveConn(ctx, conn) }
}
func serveConn(ctx context.Context, conn *quic.Conn) {
    var authenticated atomic.Bool
    go func() {
        defraggers := make(map[uint32]*proxy.Defragger)
        for {
            wire, err := conn.ReceiveDatagram(ctx); if err != nil { return }
            if !authenticated.Load() { continue }
            message, err := proxy.ParseUDPMessage(wire); if err != nil { continue }
            defragger := defraggers[message.SessionID]
            if defragger == nil { if len(defraggers) >= 16 { continue }; defragger = new(proxy.Defragger); defraggers[message.SessionID] = defragger }
            if complete := defragger.Feed(message); complete != nil { if sendMessage(conn, complete) != nil { return } }
        }
    }()
    h3server := &http3.Server{
        Handler:http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if r.Method != "POST" || r.Host != "hysteria" || r.URL.Path != "/auth" || r.Header.Get("Hysteria-Auth") != *auth { http.NotFound(w,r); return }
            authenticated.Store(true)
            w.Header().Set("Hysteria-UDP", "true"); w.Header().Set("Hysteria-CC-RX", "0"); w.WriteHeader(233)
        }),
        StreamDispatcher:func(kind http3.FrameType, stream *quic.Stream, err error) (bool,error) {
            if err != nil || !authenticated.Load() || kind != 0x401 { return false,nil }
            if _,err = quicvarint.Read(quicvarint.NewReader(stream)); err != nil { return false,err }
            go func() {
                defer stream.Close()
                target, err := proxy.ReadTCPRequest(stream); if err != nil { return }
                if target == "reject.example:443" { _ = proxy.WriteTCPResponse(stream, false, "Go peer rejected destination"); return }
                if proxy.WriteTCPResponse(stream, true, "") != nil { return }
                _, _ = io.Copy(stream, stream)
            }()
            return true,nil
        },
    }
    _ = h3server.ServeQUICConn(conn)
    _ = conn.CloseWithError(0x100, "done")
}
func sendMessage(conn *quic.Conn, message *proxy.UDPMessage) error {
    for _, fragment := range proxy.FragUDPMessage(message, 1100) {
        wire := make([]byte, fragment.Size()); if fragment.Serialize(wire) < 0 { return errors.New("Go UDP serialize failed") }
        binary.BigEndian.PutUint32(wire, fragment.SessionID)
        if err := conn.SendDatagram(wire); err != nil { return err }
    }
    return nil
}
func client(ctx context.Context) error {
    der, err := hex.DecodeString(*rootDER); if err != nil { return err }
    cert, err := x509.ParseCertificate(der); if err != nil { return err }
    roots := x509.NewCertPool(); roots.AddCert(cert)
    tlsConfig := &tls.Config{RootCAs:roots, ServerName:"localhost", NextProtos:[]string{"h3"}, MinVersion:tls.VersionTLS13}
    cfg := config(); cfg.OmitMaxDatagramFrameSize = *omitDatagram
    var conn *quic.Conn
    transport := &http3.Transport{TLSClientConfig:tlsConfig, QUICConfig:cfg,
        Dial:func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn,error) {
            connection, err := quic.DialAddrEarly(ctx,*address,tlsCfg,cfg); conn=connection; return connection,err
        },
    }
    defer transport.Close()
    request, _ := http.NewRequestWithContext(ctx, "POST", "https://hysteria/auth", nil)
    request.Header.Set("Hysteria-Auth", *auth); request.Header.Set("Hysteria-CC-RX", "0")
    response, err := transport.RoundTrip(request); if err != nil { return err }; response.Body.Close()
    if response.StatusCode != 233 { return fmt.Errorf("auth failed: %d",response.StatusCode) }
    stream, err := conn.OpenStreamSync(ctx); if err != nil { return err }; defer stream.Close()
    if _,err=stream.Write(quicvarint.Append(nil,0x401)); err != nil { return err }
    if err=proxy.WriteTCPRequest(stream,"example.com:443"); err != nil { return err }
    ok, message, err := proxy.ReadTCPResponse(stream); if err != nil { return err }; if !ok { return errors.New(message) }
    payload := []byte("Go-to-Rust-QUIC")
    if _,err=stream.Write(payload); err != nil { return err }
    // Finish only the send direction so Rust's echo copy observes EOF. Waiting
    // for its FIN below keeps deferred transport.Close from racing that copy.
    if err=stream.Close(); err != nil { return err }
    reply := make([]byte,len(payload)); if _,err=io.ReadFull(stream,reply); err != nil { return err }; if !bytes.Equal(reply,payload) { return errors.New("TCP payload mismatch") }
    var trailing [1]byte
    if n,err := stream.Read(trailing[:]); n != 0 || err != io.EOF { return fmt.Errorf("TCP echo did not finish: n=%d err=%v",n,err) }
    udp := &proxy.UDPMessage{SessionID:7,PacketID:9,FragCount:1,Addr:"dns.example:53",Data:bytes.Repeat([]byte{0x63},6000)}
    if err=sendMessage(conn,udp); err != nil { return err }
    defragger := new(proxy.Defragger)
    for {
        wire, err := conn.ReceiveDatagram(ctx); if err != nil { return err }
        message, err := proxy.ParseUDPMessage(wire); if err != nil { return err }
        complete := defragger.Feed(message); if complete == nil { continue }
        if complete.SessionID != udp.SessionID || complete.Addr != udp.Addr || !bytes.Equal(complete.Data,udp.Data) { return errors.New("UDP echo mismatch") }
        break
    }
    return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"ok":true,"omitted_datagram_parameter":*omitDatagram,"tcp_stream_finished":true})
}
