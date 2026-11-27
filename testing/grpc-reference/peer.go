// Independent peer built inside an archive of the exact Go reference commit.
// grpc-go and the pinned generated bindings own all HTTP/2/protobuf framing.
package main

import (
    "bytes"
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "net"
    "net/url"
    "os"
    "runtime"
    "strings"
    "time"

    "github.com/xtls/xray-core/common/log"
    xnet "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/transport/internet"
    gun "github.com/xtls/xray-core/transport/internet/grpc"
    "github.com/xtls/xray-core/transport/internet/grpc/encoding"
    "google.golang.org/grpc"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/metadata"
    "google.golang.org/grpc/status"
)

const reference = "67756b3674d56b72c7a7e675e8dcd3f883e1b2f7"
const requestSize = 196613
const replySize = 131079

type command struct {
    Mode string `json:"mode"`
    Address string `json:"address"`
    ServiceName string `json:"service_name"`
    MultiMode bool `json:"multi_mode"`
    Authority string `json:"authority"`
    Scenario string `json:"scenario"`
}

type event struct {
    Event string `json:"event"`
    Reference string `json:"reference"`
    Mode string `json:"mode"`
    Address string `json:"address"`
    ServiceName string `json:"service_name"`
    MultiMode bool `json:"multi_mode"`
    Authority string `json:"authority"`
    Scenario string `json:"scenario"`
    BytesSent int `json:"bytes_sent"`
    BytesReceived int `json:"bytes_received"`
}

func report(c command, kind, address string, sent, received int) error {
    return json.NewEncoder(os.Stdout).Encode(event{kind, reference, c.Mode, address,
        c.ServiceName, c.MultiMode, c.Authority, c.Scenario, sent, received})
}

func readCommand() (command, error) {
    var c command
    raw, err := io.ReadAll(io.LimitReader(os.Stdin, 65537))
    if err != nil { return c, err }
    if len(raw) > 65536 { return c, fmt.Errorf("JSON control exceeds 64 KiB") }
    // Reject duplicate keys as well as unknown fields, malformed/trailing JSON,
    // and wrong value types. No stdout logging or implicit control defaults.
    keys := json.NewDecoder(bytes.NewReader(raw))
    first, err := keys.Token()
    if err != nil || first != json.Delim('{') { return c, fmt.Errorf("expected JSON control object") }
    allowed := map[string]bool{"mode":true, "address":true, "service_name":true, "multi_mode":true, "authority":true, "scenario":true}
    seen := map[string]bool{}
    for keys.More() {
        key, err := keys.Token()
        if err != nil { return c, err }
        name, ok := key.(string)
        if !ok || seen[name] || !allowed[name] { return c, fmt.Errorf("unknown/duplicate/invalid JSON control key") }
        seen[name] = true
        var value json.RawMessage
        if err := keys.Decode(&value); err != nil { return c, err }
        if bytes.Equal(bytes.TrimSpace(value), []byte("null")) { return c, fmt.Errorf("null control field %s", name) }
    }
    if _, err := keys.Token(); err != nil { return c, err }
    decoder := json.NewDecoder(bytes.NewReader(raw))
    decoder.DisallowUnknownFields()
    if err := decoder.Decode(&c); err != nil { return c, err }
    var extra any
    if err := decoder.Decode(&extra); err != io.EOF { return c, fmt.Errorf("trailing JSON control") }
    for _, field := range []string{"mode", "address", "service_name", "multi_mode", "authority", "scenario"} {
        if !seen[field] { return c, fmt.Errorf("missing JSON control field %s", field) }
    }
    if c.Mode != "server" && c.Mode != "client" { return c, fmt.Errorf("unknown mode %q", c.Mode) }
    if c.Scenario != "roundtrip" && !(c.Mode == "server" && c.Scenario == "denied") {
        return c, fmt.Errorf("unsupported scenario %q", c.Scenario)
    }
    host, port, err := net.SplitHostPort(c.Address)
    if err != nil { return c, err }
    ip := net.ParseIP(host)
    if ip == nil || !ip.IsLoopback() || ip.To4() == nil { return c, fmt.Errorf("IPv4 loopback required") }
    if c.Mode == "client" && port == "0" { return c, fmt.Errorf("client port must be nonzero") }
    if c.Authority != "gun.reference.invalid:8443" { return c, fmt.Errorf("unexpected authority") }
    return c, nil
}

func payload(n, salt int) []byte {
    p := make([]byte, n)
    for i := range p { p[i] = byte(i*73 + i/251 + salt) }
    return p
}

func serviceNames(name string) (string, string, string) {
    // Standard-library URL escaping, independently from the Rust adapter.
    if !strings.HasPrefix(name, "/") { return url.PathEscape(name), "Tun", "TunMulti" }
    last := strings.LastIndex(name, "/")
    stop := last
    if stop < 1 { stop = 1 }
    parts := strings.Split(name[1:stop], "/")
    for i := range parts { parts[i] = url.PathEscape(parts[i]) }
    methods := strings.Split(name[last+1:], "|")
    tun, multi := methods[0], methods[0]
    if len(methods) > 1 { multi = methods[1] }
    return strings.Join(parts, "/"), url.PathEscape(tun), url.PathEscape(multi)
}

type peerServer struct {
    encoding.UnimplementedGRPCServiceServer
    c command
    done chan error
}

func (s *peerServer) run(ctx context.Context, conn net.Conn, multi bool, send func([]byte) error) (result error) {
    defer func() { s.done <- result }()
    if multi != s.c.MultiMode { return fmt.Errorf("wrong Gun mode") }
    md, ok := metadata.FromIncomingContext(ctx)
    if !ok || len(md.Get(":authority")) != 1 || md.Get(":authority")[0] != s.c.Authority {
        return fmt.Errorf("authority not preserved")
    }
    if len(md.Get("user-agent")) != 1 || md.Get("user-agent")[0] != "p0u27-rust" {
        return fmt.Errorf("literal user-agent not preserved")
    }
    got := make([]byte, requestSize)
    if _, err := io.ReadFull(conn, got); err != nil { return err }
    if !bytes.Equal(got, payload(requestSize, 19)) { return fmt.Errorf("request bytes differ") }
    var extra [1]byte
    if n, err := conn.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
        return fmt.Errorf("request half-close: n=%d err=%v", n, err)
    }
    if s.c.Scenario == "denied" { return nil }
    return send(payload(replySize, 167))
}

func (s *peerServer) Tun(stream encoding.GRPCService_TunServer) error {
    err := s.run(stream.Context(), encoding.NewHunkConn(stream, nil, nil), false, func(reply []byte) error {
        if err := stream.Send(&encoding.Hunk{}); err != nil { return err }
        // One record is larger than the HTTP/2 receive window, and boundaries
        // are deliberately unrelated to Rust's 16 KiB write chunks.
        for _, p := range [][]byte{reply[:1], reply[1:16388], reply[16388:]} {
            if err := stream.Send(&encoding.Hunk{Data:p}); err != nil { return err }
        }
        return nil
    })
    if err != nil { return status.Error(codes.Internal, err.Error()) }
    if s.c.Scenario == "denied" { return status.Error(codes.PermissionDenied, "denied: 100% café") }
    return nil
}

func (s *peerServer) TunMulti(stream encoding.GRPCService_TunMultiServer) error {
    err := s.run(stream.Context(), encoding.NewMultiHunkConn(stream, nil, nil), true, func(reply []byte) error {
        if err := stream.Send(&encoding.MultiHunk{}); err != nil { return err }
        return stream.Send(&encoding.MultiHunk{Data:[][]byte{nil, reply[:1], {}, reply[1:8193], reply[8193:]}})
    })
    if err != nil { return status.Error(codes.Internal, err.Error()) }
    if s.c.Scenario == "denied" { return status.Error(codes.PermissionDenied, "denied: 100% café") }
    return nil
}

func serve(c command) error {
    listener, err := net.Listen("tcp4", c.Address)
    if err != nil { return err }
    defer listener.Close()
    s := grpc.NewServer()
    defer s.Stop()
    peer := &peerServer{c:c, done:make(chan error, 1)}
    name, tun, multi := serviceNames(c.ServiceName)
    if tun == multi { return fmt.Errorf("server methods must be distinct") }
    encoding.RegisterGRPCServiceServerX(s, peer, name, tun, multi)
    served := make(chan error, 1)
    go func() { served <- s.Serve(listener) }()
    if err := report(c, "ready", listener.Addr().String(), 0, 0); err != nil { return err }
    select {
    case err := <-peer.done:
        if err != nil { return err }
    case err := <-served:
        return fmt.Errorf("gRPC server stopped before exchange: %v", err)
    }
    // Wait for the handler return and grpc-go's final trailers before exit.
    s.GracefulStop()
    sent := replySize
    if c.Scenario == "denied" { sent = 0 }
    return report(c, "done", listener.Addr().String(), sent, requestSize)
}

func connect(c command) error {
    // This direction exercises the pinned production Gun dialer, including
    // its custom path selection, authority, and native MultiBuffer adapter.
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    endpoint, err := xnet.ParseDestination("tcp:" + c.Address)
    if err != nil { return err }
    settings := &internet.MemoryStreamConfig{ProtocolName:"grpc", ProtocolSettings:&gun.Config{
        ServiceName:c.ServiceName, MultiMode:c.MultiMode, Authority:c.Authority, UserAgent:"golang",
    }}
    conn, err := gun.Dial(ctx, endpoint, settings)
    if err != nil { return err }
    defer conn.Close()
    request := payload(requestSize, 19)
    if n, err := conn.Write(request); err != nil || n != len(request) { return fmt.Errorf("request write: n=%d err=%v", n, err) }
    reply := make([]byte, replySize)
    if _, err := io.ReadFull(conn, reply); err != nil { return err }
    if !bytes.Equal(reply, payload(replySize, 167)) { return fmt.Errorf("response bytes differ") }
    var extra [1]byte
    if n, err := conn.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
        return fmt.Errorf("response status/EOF: n=%d err=%v", n, err)
    }
    return report(c, "done", c.Address, requestSize, replySize)
}

func main() {
    log.RegisterHandler(log.NewLogger(log.CreateStderrLogWriter()))
    if runtime.GOOS != "linux" || len(os.Args) != 1 {
        fmt.Fprintln(os.Stderr, "Linux only; pass exactly one strict JSON control object on stdin, then EOF")
        os.Exit(1)
    }
    watchdog := time.AfterFunc(35*time.Second, func() {
        fmt.Fprintln(os.Stderr, "pinned gRPC peer exceeded 35s deadline")
        os.Exit(1)
    })
    defer watchdog.Stop()
    c, err := readCommand()
    if err == nil {
        if c.Mode == "server" { err = serve(c) } else { err = connect(c) }
    }
    if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}
