// Independent interoperability oracle. This file imports no Rust implementation
// and uses the exact wireguard-go, gVisor and x/crypto versions in Go's go.mod.
package main

import (
    "bufio"
    "context"
    "encoding/hex"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "net/netip"
    "os"
    "strings"
    "time"

    "golang.org/x/crypto/curve25519"
    "golang.zx2c4.com/wireguard/conn"
    "golang.zx2c4.com/wireguard/device"
    "golang.zx2c4.com/wireguard/tun/netstack"
)

const aliceSecret = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
const bobSecret = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"

func fail(err error) { if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) } }
func emit(value any) { fail(json.NewEncoder(os.Stdout).Encode(value)) }
func referenceLogger(stderr io.Writer) *device.Logger {
    // wireguard-go's NewLogger writes errors to stdout. A serving peer's
    // initial keepalive has no known endpoint yet; that diagnostic must not
    // precede the readiness JSON on the machine-readable stdout channel.
    return &device.Logger{Verbosef: device.DiscardLogf,
        Errorf: log.New(stderr, "go-reference: ", log.LstdFlags).Printf}
}
func public(secret string) string {
    key, err := hex.DecodeString(secret); fail(err)
    if len(key) != 32 { fail(fmt.Errorf("private key must be 32 bytes")) }
    result, err := curve25519.X25519(key, curve25519.Basepoint); fail(err)
    return hex.EncodeToString(result)
}

func main() {
    mode := flag.String("mode", "serve", "serve, probe-tcp, probe-udp, or vectors")
    secret := flag.String("private-key", bobSecret, "hex private key")
    peer := flag.String("peer-public-key", public(aliceSecret), "hex peer public key")
    psk := flag.String("preshared-key", "", "optional hex preshared key")
    endpoint := flag.String("peer-endpoint", "", "optional UDP peer endpoint")
    addresses := flag.String("addresses", "10.77.0.1,fd77::1", "comma separated interface addresses")
    target := flag.String("target", "10.77.0.2:9000", "probe target through WireGuard")
    payloadHex := flag.String("payload", "7769726567756172642d676f2d70726f6265", "hex probe payload")
    mtu := flag.Int("mtu", 1420, "inner IP MTU")
    keepalive := flag.Uint("keepalive", 1, "persistent keepalive seconds")
    flag.Parse()
    if *mode == "vectors" {
        emit(map[string]any{"source": "Go curve25519.X25519; RFC 7748 section 6.1 secrets",
            "aliceSecret": aliceSecret, "alicePublic": public(aliceSecret),
            "bobSecret": bobSecret, "bobPublic": public(bobSecret)})
        return
    }
    ips := []netip.Addr{}
    for _, text := range strings.Split(*addresses, ",") { ips = append(ips, netip.MustParseAddr(text)) }
    tun, stack, err := netstack.CreateNetTUN(ips, nil, *mtu); fail(err)
    dev := device.NewDevice(tun, conn.NewDefaultBind(), referenceLogger(os.Stderr))
    defer dev.Close()
    ipc := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=%d\n", *secret, *peer, *keepalive)
    if *psk != "" { ipc += "preshared_key=" + *psk + "\n" }
    if *endpoint != "" { ipc += "endpoint=" + *endpoint + "\n" }
    fail(dev.IpcSet(ipc)); fail(dev.Up())
    status, err := dev.IpcGet(); fail(err)
    port := ""
    for _, line := range strings.Split(status, "\n") { if strings.HasPrefix(line, "listen_port=") { port = strings.TrimPrefix(line, "listen_port=") } }
    if port == "" || port == "0" { fail(fmt.Errorf("device did not expose bound port")) }
    if *mode == "serve" {
        tcpAddresses, udpAddresses := []string{}, []string{}
        for _, ip := range ips {
            tcpAddr := netip.AddrPortFrom(ip, 9000)
            listener, err := stack.ListenTCPAddrPort(tcpAddr); fail(err)
            defer listener.Close()
            tcpAddresses = append(tcpAddresses, tcpAddr.String())
            go func() { for { c, err := listener.Accept(); if err != nil { return }; go func() { defer c.Close(); _, _ = io.Copy(c, c) }() } }()
            udpAddr := netip.AddrPortFrom(ip, 9001)
            socket, err := stack.ListenUDPAddrPort(udpAddr); fail(err)
            defer socket.Close()
            udpAddresses = append(udpAddresses, udpAddr.String())
            go func() { buffer := make([]byte, 65535); for { n, remote, err := socket.ReadFrom(buffer); if err != nil { return }; _, _ = socket.WriteTo(buffer[:n], remote) } }()
        }
        emit(map[string]any{"endpoint": "127.0.0.1:" + port, "publicKey": public(*secret), "tcpAddresses": tcpAddresses, "udpAddresses": udpAddresses})
        scanner := bufio.NewScanner(os.Stdin)
        for scanner.Scan() { if scanner.Text() == "quit" { return } }
        return
    }
    payload, err := hex.DecodeString(*payloadHex); fail(err)
    ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second); defer cancel()
    var c net.Conn
    switch *mode {
    case "probe-tcp": c, err = stack.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort(*target))
    case "probe-udp": c, err = stack.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort(*target))
    default: fail(fmt.Errorf("unknown mode %q", *mode))
    }
    fail(err); defer c.Close(); fail(c.SetDeadline(time.Now().Add(20*time.Second)))
    _, err = c.Write(payload); fail(err)
    reply := make([]byte, len(payload)); _, err = io.ReadFull(c, reply); fail(err)
    emit(map[string]any{"reply": hex.EncodeToString(reply), "publicKey": public(*secret)})
}
