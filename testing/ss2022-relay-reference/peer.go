// Live relay acceptance only. SS2022 crypto and handlers are production Go.
// Build inside an isolated archive of reference using build-peer.sh on Linux.
package main

import (
    "bufio"
    "bytes"
    "context"
    "encoding/base64"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "io"
    "net"
    "os"
    "runtime"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/common/log"
    xnet "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/protocol"
    "github.com/xtls/xray-core/common/serial"
    "github.com/xtls/xray-core/common/session"
    "github.com/xtls/xray-core/core"
    "github.com/xtls/xray-core/features/routing"
    "github.com/xtls/xray-core/proxy"
    ss "github.com/xtls/xray-core/proxy/shadowsocks_2022"
    "github.com/xtls/xray-core/transport"
    "github.com/xtls/xray-core/transport/internet/stat"
    "github.com/xtls/xray-core/transport/pipe"
)

const reference = "67756b3674d56b72c7a7e675e8dcd3f883e1b2f7"
const packetCount, sessionCount, wireLimit = 6, 2, 8192
const finalEmail, finalLevel = "relay-final@example.invalid", 7
const lifetime = 45 * time.Second

type scenario struct { method, role string; keys [][]byte }
type event struct {
    Event string `json:"event"`
    Source string `json:"source"`
    Mode string `json:"mode"`
    Method string `json:"method"`
    Role string `json:"role"`
    Layer int `json:"layer"`
    Path string `json:"path"`
    Address string `json:"address"`
    Peer string `json:"peer"`
    Next string `json:"next"`
    Email string `json:"email"`
    Level uint32 `json:"level"`
    Packets int `json:"packets"`
    Sessions int `json:"sessions"`
    Wire string `json:"wire"`
}
type reporter struct {
    mu sync.Mutex
    mode string
    layer int
    s scenario
    lines, bytes int
}
func (r *reporter) emit(e event) error {
    r.mu.Lock()
    defer r.mu.Unlock()
    e.Source, e.Mode, e.Method, e.Role, e.Layer = reference, r.mode, r.s.method, r.s.role, r.layer
    data, err := json.Marshal(e)
    if err != nil { return err }
    data = append(data, '\n')
    if len(data) > 16384 || r.lines >= 64 || r.bytes+len(data) > 192*1024 { return fmt.Errorf("bounded JSON output exceeded") }
    r.lines++
    r.bytes += len(data)
    n, err := os.Stdout.Write(data)
    if err == nil && n != len(data) { err = io.ErrShortWrite }
    return err
}
func (r *reporter) wire(kind, path string, local, remote net.Addr, wire []byte) error {
    if len(wire) == 0 || len(wire) > wireLimit { return fmt.Errorf("invalid encrypted packet length %d", len(wire)) }
    return r.emit(event{Event: kind, Path: path, Address: local.String(), Peer: remote.String(), Wire: base64.StdEncoding.EncodeToString(wire)})
}
func key(size int, first byte) []byte {
    out := make([]byte, size)
    for i := range out { out[i] = first + byte(i) }
    return out
}
func newScenario(method, role string) (scenario, error) {
    s := scenario{method: method, role: role}
    size := 16
    if method == ss.MethodAES256GCM { size = 32 } else if method != ss.MethodAES128GCM { return s, fmt.Errorf("AES128/AES256 relay only") }
    if role != "single" && role != "multi" { return s, fmt.Errorf("single/multi final endpoint required") }
    s.keys = [][]byte{key(size, 0x81), key(size, 0xa1)}
    if role == "multi" { s.keys = append(s.keys, key(size, 0xc1)) }
    s.keys = append(s.keys, key(size, 0x11))
    return s, nil
}
func encoded(keys [][]byte) string {
    parts := make([]string, len(keys))
    for i, key := range keys { parts[i] = base64.StdEncoding.EncodeToString(key) }
    return strings.Join(parts, ":")
}
func hopEmail(layer int) string { return fmt.Sprintf("relay-hop-%d@example.invalid", layer) }
func destination(index int, reply bool) xnet.Destination {
    addresses := []string{"empty.example.invalid:443", "203.0.113.7:5353", "[2001:db8::7]:9000", "large.example.invalid:8443", "198.51.100.8:9001", "[2001:db8::8]:5353"}
    if reply { addresses = []string{"[2001:db8::50]:9443", "198.51.100.70:5354", "response.example.invalid:9002", "[2001:db8::51]:8444", "last.example.invalid:9003", "empty-reply.example.invalid:5354"} }
    value, err := xnet.ParseDestination("udp:" + addresses[index])
    if err != nil { panic(err) }
    return value
}
func payload(index int, reply bool) []byte {
    sizes, salt := []int{0, 1, 257, 7900, 19, 0}, 0x31
    if reply { sizes, salt = []int{0, 19, 513, 7800, 1, 0}, 0xa7 }
    out := make([]byte, sizes[index])
    for i := range out { out[i] = byte(i*73 + i/251 + salt + index*17) }
    return out
}
func same(a, b xnet.Destination) bool { return a.Network == b.Network && a.Port == b.Port && a.Address.String() == b.Address.String() }
func packet(index int, reply bool) *buf.Buffer {
    b := buf.FromBytes(payload(index, reply))
    d := destination(index, reply)
    b.UDP = &d
    return b
}
func check(index int, reply bool, b *buf.Buffer) error {
    if b == nil || b.UDP == nil || !same(*b.UDP, destination(index, reply)) || !bytes.Equal(b.Bytes(), payload(index, reply)) { return fmt.Errorf("packet %d reply=%t binary/address mismatch", index, reply) }
    return nil
}
func resolve(address string, nonzero bool) (*net.UDPAddr, error) {
    a, err := net.ResolveUDPAddr("udp4", address)
    if err != nil { return nil, err }
    if !a.IP.IsLoopback() || (nonzero && a.Port == 0) { return nil, fmt.Errorf("expected loopback UDP address: %s", address) }
    return a, nil
}
func waitExit() error {
    line, err := bufio.NewReader(io.LimitReader(os.Stdin, 16)).ReadString('\n')
    if err != nil || line != "exit\n" { return fmt.Errorf("expected bounded exit control, got %q: %v", line, err) }
    return nil
}
func checkReleased(socket *net.UDPConn) error {
    // ReadFromUDP checks closure for both connected and listening sockets;
    // WriteToUDP on a connected socket can instead report ErrWriteToConnected.
    if n, _, err := socket.ReadFromUDP(make([]byte, 1)); n != 0 || !errors.Is(err, net.ErrClosed) { return fmt.Errorf("read after close: %d %v", n, err) }
    probe, err := net.ListenUDP("udp4", socket.LocalAddr().(*net.UDPAddr))
    if err != nil { return fmt.Errorf("socket not released: %w", err) }
    return probe.Close()
}
func readWire(socket *net.UDPConn) ([]byte, *net.UDPAddr, error) {
    var data [wireLimit+1]byte
    n, remote, err := socket.ReadFromUDP(data[:])
    if err != nil { return nil, nil, err }
    if n == 0 || n > wireLimit { return nil, nil, fmt.Errorf("encrypted datagram length %d", n) }
    return append([]byte(nil), data[:n]...), remote, nil
}

// Adapters below do not encode, decode or rewrite any SS2022 bytes.
// One production inbound instance is shared across bounded per-peer Process
// calls, so its real session manager must perform physical-address rebinding.
type peerConn struct {
    *net.UDPConn
    host *host
    remote *net.UDPAddr
    incoming chan []byte
}
func (c *peerConn) Read(out []byte) (int, error) {
    select {
    case wire := <-c.incoming:
        if len(wire) > len(out) { return 0, io.ErrShortBuffer }
        return copy(out, wire), nil
    case <-c.host.ctx.Done(): return 0, net.ErrClosed
    }
}
func (c *peerConn) RemoteAddr() net.Addr { return c.remote }
func (c *peerConn) Close() error { return nil } // host owns the shared listener
func (c *peerConn) Write(wire []byte) (int, error) {
    if err := c.host.r.wire("response", "handler", c.LocalAddr(), c.remote, wire); err != nil { c.host.fail(err); return 0, err }
    n, err := c.WriteToUDP(wire, c.remote)
    if err == nil && n != len(wire) { err = io.ErrShortWrite }
    if err != nil { c.host.fail(err); return n, err }
    count := c.host.responses.Add(1)
    if count == packetCount { close(c.host.complete) } else if count > packetCount { c.host.fail(fmt.Errorf("unexpected extra response")) }
    return n, nil
}
type host struct {
    ctx context.Context
    socket *net.UDPConn
    r *reporter
    peers map[string]*peerConn
    workers sync.WaitGroup
    readDone chan struct{}
    failures chan error
    complete chan struct{}
    requests, responses atomic.Int32
}
func (h *host) fail(err error) { if err != nil { select { case h.failures <- err: default: } } }
func (h *host) read(inbound proxy.Inbound, dispatcher routing.Dispatcher) {
    defer close(h.readDone)
    for {
        wire, remote, err := readWire(h.socket)
        if err != nil { if h.ctx.Err() == nil { h.fail(err) }; return }
        if h.requests.Add(1) > packetCount { h.fail(fmt.Errorf("unexpected extra request")); return }
        if err := h.r.wire("request", "handler", h.socket.LocalAddr(), remote, wire); err != nil { h.fail(err); return }
        conn := h.peers[remote.String()]
        if conn == nil {
            if len(h.peers) >= 4 { h.fail(fmt.Errorf("peer bound exceeded")); return }
            conn = &peerConn{UDPConn: h.socket, host: h, remote: remote, incoming: make(chan []byte, 8)}
            h.peers[remote.String()] = conn
            processCtx := session.ContextWithInbound(h.ctx, &session.Inbound{Source: xnet.DestinationFromAddr(remote), Local: xnet.DestinationFromAddr(h.socket.LocalAddr()), Tag: "go-relay-live"})
            h.workers.Add(1)
            go func(c *peerConn, ctx context.Context) {
                defer h.workers.Done()
                err := inbound.Process(ctx, xnet.Network_UDP, c, dispatcher)
                if h.ctx.Err() == nil { h.fail(fmt.Errorf("production inbound ended early: %v", err)) }
            }(conn, processCtx)
        }
        select { case conn.incoming <- wire: default: h.fail(fmt.Errorf("peer queue bound exceeded")); return }
    }
}

type endpointLink struct { ctx context.Context; cases []int; index int; responses chan buf.MultiBuffer; fail func(error) }
func (e *endpointLink) ReadMultiBuffer() (buf.MultiBuffer, error) {
    select { case b := <-e.responses: return b, nil; case <-e.ctx.Done(): return nil, e.ctx.Err() }
}
func (e *endpointLink) WriteMultiBuffer(mb buf.MultiBuffer) error {
    defer buf.ReleaseMulti(mb)
    for _, b := range mb {
        if e.index >= len(e.cases) { err := fmt.Errorf("extra endpoint packet"); e.fail(err); return err }
        index := e.cases[e.index]
        if err := check(index, false, b); err != nil { e.fail(err); return err }
        e.index++
        reply := buf.MultiBuffer{packet(index, true)}
        select { case e.responses <- reply: case <-e.ctx.Done(): buf.ReleaseMulti(reply); return e.ctx.Err() }
    }
    return nil
}
type directLink struct { socket *net.UDPConn; r *reporter; fail func(error) }
func (d *directLink) ReadMultiBuffer() (buf.MultiBuffer, error) {
    wire, _, err := readWire(d.socket)
    if err != nil { return nil, err }
    if err := d.r.wire("reply", "handler", d.socket.LocalAddr(), d.socket.RemoteAddr(), wire); err != nil { d.fail(err); return nil, err }
    return buf.MultiBuffer{buf.FromBytes(wire)}, nil
}
func (d *directLink) WriteMultiBuffer(mb buf.MultiBuffer) error {
    defer buf.ReleaseMulti(mb)
    for _, b := range mb {
        if err := d.r.wire("forward", "handler", d.socket.LocalAddr(), d.socket.RemoteAddr(), b.Bytes()); err != nil { d.fail(err); return err }
        n, err := d.socket.Write(b.Bytes())
        if err == nil && n != len(b.Bytes()) { err = io.ErrShortWrite }
        if err != nil { d.fail(err); return err }
    }
    return nil
}
type dispatcher struct {
    h *host
    next *net.UDPAddr
    mu sync.Mutex
    calls int
    links []*directLink
    endpoints []*endpointLink
}
func (*dispatcher) Type() interface{} { return routing.DispatcherType() }
func (*dispatcher) Start() error { return nil }
func (*dispatcher) Close() error { return nil }
func (*dispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error { return fmt.Errorf("unexpected DispatchLink") }
func (d *dispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
    d.mu.Lock()
    defer d.mu.Unlock()
    if err := d.h.ctx.Err(); err != nil { return nil, err }
    d.calls++
    in := session.InboundFromContext(ctx)
    email, level := finalEmail, uint32(finalLevel)
    if d.next != nil { email, level = hopEmail(d.h.r.layer), uint32(10+d.h.r.layer) }
    if d.calls > sessionCount || in == nil || in.User == nil || in.User.Email != email || in.User.Level != level || !in.Source.Address.IP().IsLoopback() {
        err := fmt.Errorf("production inbound user/source/session-count mismatch"); d.h.fail(err); return nil, err
    }
    e := event{Event: "dispatch", Path: "handler", Address: d.h.socket.LocalAddr().String(), Peer: in.Source.NetAddr(), Email: email, Level: level, Sessions: d.calls}
    if d.next != nil {
        if !same(dest, xnet.DestinationFromAddr(d.next)) { err := fmt.Errorf("relay next-hop destination/network mismatch"); d.h.fail(err); return nil, err }
        socket, err := net.DialUDP("udp4", nil, d.next)
        if err != nil { d.h.fail(err); return nil, err }
        deadline, _ := d.h.ctx.Deadline()
        if err := socket.SetDeadline(deadline); err != nil { socket.Close(); d.h.fail(err); return nil, err }
        link := &directLink{socket: socket, r: d.h.r, fail: d.h.fail}
        d.links = append(d.links, link)
        e.Next = dest.NetAddr()
        if err := d.h.r.emit(e); err != nil { d.h.fail(err); return nil, err }
        return &transport.Link{Reader: link, Writer: link}, nil
    }
    cases := []int{1,2,3,4}
    if same(dest, destination(0, false)) { cases = []int{0,5} } else if !same(dest, destination(1, false)) { err := fmt.Errorf("endpoint initial destination mismatch"); d.h.fail(err); return nil, err }
    link := &endpointLink{ctx: d.h.ctx, cases: cases, responses: make(chan buf.MultiBuffer, 4), fail: d.h.fail}
    d.endpoints = append(d.endpoints, link)
    e.Next = dest.NetAddr()
    if err := d.h.r.emit(e); err != nil { d.h.fail(err); return nil, err }
    return &transport.Link{Reader: link, Writer: link}, nil
}
func inboundObject(instance *core.Instance, r *reporter, next *net.UDPAddr) (proxy.Inbound, error) {
    s := r.s
    var config interface{}
    if r.mode == "relay" {
        destinations := []*ss.RelayDestination{}
        for i, psk := range [][]byte{key(len(s.keys[0]), 0x51), s.keys[r.layer+1]} {
            email := "decoy@example.invalid"
            if i == 1 { email = hopEmail(r.layer) }
            destinations = append(destinations, &ss.RelayDestination{Key: encoded([][]byte{psk}), Address: xnet.NewIPOrDomain(xnet.IPAddress(next.IP)), Port: uint32(next.Port), Email: email, Level: int32(10+r.layer)})
        }
        config = &ss.RelayServerConfig{Method: s.method, Key: encoded(s.keys[r.layer:r.layer+1]), Destinations: destinations, Network: []xnet.Network{xnet.Network_UDP}}
    } else if s.role == "single" {
        config = &ss.ServerConfig{Method: s.method, Key: encoded(s.keys[2:]), Email: finalEmail, Level: finalLevel, Network: []xnet.Network{xnet.Network_UDP}}
    } else {
        users := []*protocol.User{}
        for i, psk := range [][]byte{key(len(s.keys[0]), 0x51), s.keys[3]} {
            email := "decoy@example.invalid"
            if i == 1 { email = finalEmail }
            users = append(users, &protocol.User{Email: email, Level: finalLevel, Account: serial.ToTypedMessage(&ss.Account{Key: encoded([][]byte{psk})})})
        }
        config = &ss.MultiUserServerConfig{Method: s.method, Key: encoded(s.keys[2:3]), Users: users, Network: []xnet.Network{xnet.Network_UDP}}
    }
    object, err := core.CreateObject(instance, config) // NewRelayServer/NewServer/NewMultiServer
    if err != nil { return nil, err }
    return object.(proxy.Inbound), nil
}
func serve(ctx context.Context, instance *core.Instance, r *reporter, address, next *net.UDPAddr) error {
    inbound, err := inboundObject(instance, r, next)
    if err != nil { return err }
    socket, err := net.ListenUDP("udp4", address)
    if err != nil { return err }
    defer socket.Close()
    deadline, _ := ctx.Deadline()
    if err := socket.SetDeadline(deadline); err != nil { return err }
    hostCtx, cancel := context.WithCancel(ctx)
    defer cancel()
    h := &host{ctx: hostCtx, socket: socket, r: r, peers: make(map[string]*peerConn), readDone: make(chan struct{}), failures: make(chan error, 1), complete: make(chan struct{})}
    d := &dispatcher{h: h, next: next}
    var stopped sync.Once
    shutdown := func() {
        stopped.Do(func() {
            cancel()
            socket.Close()
            <-h.readDone // no new Process workers can be started
            d.mu.Lock() // cancelled Dispatch cannot add another direct socket
            for _, link := range d.links { link.socket.Close() }
            d.mu.Unlock()
            h.workers.Wait() // closed direct sockets also wake blocked writes
        })
    }
    go h.read(inbound, d)
    defer shutdown()
    e := event{Event: "ready", Path: "handler", Address: socket.LocalAddr().String()}
    if next != nil { e.Next = next.String() }
    if err := r.emit(e); err != nil { return err }
    select { case <-h.complete: case err := <-h.failures: return err; case <-ctx.Done(): return ctx.Err() }
    d.mu.Lock()
    valid := d.calls == sessionCount
    if next == nil {
        valid = valid && len(d.endpoints) == sessionCount
        for _, link := range d.endpoints { valid = valid && link.index == len(link.cases) }
    } else { valid = valid && len(d.links) == sessionCount }
    d.mu.Unlock()
    if !valid || h.requests.Load() != packetCount { return fmt.Errorf("production session/packet completion mismatch") }
    e.Event, e.Packets, e.Sessions = "complete", packetCount, sessionCount
    if err := r.emit(e); err != nil { return err }
    if err := waitExit(); err != nil { return err }
    shutdown()
    if err := checkReleased(socket); err != nil { return err }
    for _, link := range d.links { if err := checkReleased(link.socket); err != nil { return err } }
    select { case err := <-h.failures: return err; default: }
    e.Event = "closed"
    return r.emit(e)
}

// Connected socket tracing observes bytes; all client encryption/decryption
// comes from NewClient.Process or exported production UDP session APIs.
type tracedConn struct { *net.UDPConn; r *reporter; path string }
func (c *tracedConn) Write(wire []byte) (int, error) {
    if err := c.r.wire("request", c.path, c.LocalAddr(), c.RemoteAddr(), wire); err != nil { return 0, err }
    n, err := c.UDPConn.Write(wire)
    if err == nil && n != len(wire) { err = io.ErrShortWrite }
    return n, err
}
func (c *tracedConn) Read(out []byte) (int, error) {
    var data [wireLimit+1]byte
    n, err := c.UDPConn.Read(data[:])
    if err != nil { return 0, err }
    if n > len(out) || n > wireLimit { return 0, io.ErrShortBuffer }
    if err := c.r.wire("reply", c.path, c.LocalAddr(), c.RemoteAddr(), data[:n]); err != nil { return 0, err }
    return copy(out, data[:n]), nil
}
type dialer struct { remote *net.UDPAddr; r *reporter; dialed chan *tracedConn }
func (*dialer) DestIpAddress() xnet.IP { return xnet.LocalHostIP.IP() }
func (*dialer) SetOutboundGateway(context.Context, *session.Outbound) {}
func (d *dialer) Dial(ctx context.Context, destination xnet.Destination) (stat.Connection, error) {
    if !same(destination, xnet.DestinationFromAddr(d.remote)) { return nil, fmt.Errorf("client selected wrong UDP transport") }
    var nd net.Dialer
    conn, err := nd.DialContext(ctx, "udp4", d.remote.String())
    if err != nil { return nil, err }
    socket := conn.(*net.UDPConn)
    deadline, _ := ctx.Deadline()
    if err := socket.SetDeadline(deadline); err != nil { socket.Close(); return nil, err }
    traced := &tracedConn{UDPConn: socket, r: d.r, path: "handler"}
    select { case d.dialed <- traced: return traced, nil; case <-ctx.Done(): socket.Close(); return nil, ctx.Err() }
}
type collector struct { index int; results chan error }
func (c *collector) WriteMultiBuffer(mb buf.MultiBuffer) error {
    defer buf.ReleaseMulti(mb)
    for _, b := range mb {
        err := fmt.Errorf("unexpected extra client reply")
        if c.index < 5 { err = check(c.index, true, b) }
        c.index++
        select { case c.results <- err: default: return fmt.Errorf("reply queue bound exceeded") }
        if err != nil { return err }
    }
    return nil
}
func connect(ctx context.Context, instance *core.Instance, r *reporter, remote *net.UDPAddr) error {
    object, err := core.CreateObject(instance, &ss.ClientConfig{Method: r.s.method, Key: encoded(r.s.keys), Address: xnet.NewIPOrDomain(xnet.IPAddress(remote.IP)), Port: uint32(remote.Port)})
    if err != nil { return err }
    processCtx, cancel := context.WithCancel(ctx)
    defer cancel()
    processCtx = session.ContextWithOutbounds(processCtx, []*session.Outbound{{Target: destination(1, false)}})
    requests, writer := pipe.New()
    defer writer.Close()
    defer requests.Interrupt()
    replies := &collector{index: 1, results: make(chan error, packetCount)}
    dial := &dialer{remote: remote, r: r, dialed: make(chan *tracedConn, 1)}
    finished := make(chan error, 1)
    go func() { finished <- object.(proxy.Outbound).Process(processCtx, &transport.Link{Reader: requests, Writer: replies}, dial) }()
    var conn *tracedConn
    select { case conn = <-dial.dialed: case err := <-finished: return fmt.Errorf("client ended before dial: %v", err); case <-ctx.Done(): return ctx.Err() }
    defer conn.Close()
    e := event{Event: "ready", Path: "handler", Address: conn.LocalAddr().String(), Peer: remote.String(), Sessions: 1}
    if err := r.emit(e); err != nil { return err }
    for index := 1; index < 5; index++ {
        if err := writer.WriteMultiBuffer(buf.MultiBuffer{packet(index, false)}); err != nil { return err }
        select { case err := <-replies.results: if err != nil { return err }; case err := <-finished: return fmt.Errorf("client ended at %d: %v", index, err); case <-ctx.Done(): return ctx.Err() }
    }
    e.Event, e.Packets = "handler_complete", 4
    if err := r.emit(e); err != nil { return err }
    cancel()
    select { case err := <-finished: if !errors.Is(err, context.Canceled) { return fmt.Errorf("client cancellation: %v", err) }; case <-ctx.Done(): return ctx.Err() }
    // task.Run can return on cancellation before its request copy exits.
    // Release its owned pipe before the empty-session/rebinding phase.
    requests.Interrupt()
    if err := checkReleased(conn.UDPConn); err != nil { return err }
    e.Event = "handler_closed"
    if err := r.emit(e); err != nil { return err }
    // Pinned Process's buf.Copy drops empties. Do not label these Process
    // coverage: use its real UDPWriter/UDPReader with one shared session and
    // two simultaneously open sockets, forcing relay-session rebinding.
    method, err := ss.GetCipherMethod(r.s.method)
    if err != nil { return err }
    codec, err := ss.NewUDPPacketCodec(method, r.s.keys)
    if err != nil { return err }
    session, err := codec.NewClientSession()
    if err != nil { return err }
    sockets := make([]*tracedConn, 0, 2)
    defer func() { for _, socket := range sockets { socket.Close() } }()
    for position, index := range []int{0,5} {
        socket, err := net.DialUDP("udp4", nil, remote)
        if err != nil { return err }
        deadline, _ := ctx.Deadline()
        if err := socket.SetDeadline(deadline); err != nil { socket.Close(); return err }
        traced := &tracedConn{UDPConn: socket, r: r, path: "session"}
        sockets = append(sockets, traced)
        e.Event, e.Path, e.Address, e.Packets, e.Sessions = "empty_ready", "session", socket.LocalAddr().String(), position, 1
        if position == 1 { e.Event = "empty_rebind"; if sockets[0].LocalAddr().String() == e.Address { return fmt.Errorf("empty socket did not rebind") } }
        if err := r.emit(e); err != nil { return err }
        writer := &ss.UDPWriter{Writer: traced, Session: session, Destination: destination(index, false)}
        reader := &ss.UDPReader{Reader: traced, Session: session}
        if err := writer.WriteMultiBuffer(buf.MultiBuffer{packet(index, false)}); err != nil { return err }
        mb, err := reader.ReadMultiBuffer()
        if err != nil { buf.ReleaseMulti(mb); return err }
        if len(mb) != 1 { buf.ReleaseMulti(mb); return fmt.Errorf("expected one empty reply") }
        err = check(index, true, mb[0])
        buf.ReleaseMulti(mb)
        if err != nil { return err }
    }
    if err := sockets[0].SetReadDeadline(time.Now().Add(10*time.Millisecond)); err != nil { return err }
    if _, err := sockets[0].UDPConn.Read(make([]byte, wireLimit+1)); err == nil { return fmt.Errorf("reply leaked to old peer") } else if e, ok := err.(net.Error); !ok || !e.Timeout() { return fmt.Errorf("old peer read: %v", err) }
    for _, socket := range sockets { if err := socket.Close(); err != nil { return err }; if err := checkReleased(socket.UDPConn); err != nil { return err } }
    e.Event, e.Path, e.Packets, e.Sessions = "complete", "handler+session", packetCount, sessionCount
    if err := r.emit(e); err != nil { return err }
    if err := waitExit(); err != nil { return err }
    e.Event = "closed"
    return r.emit(e)
}
func main() {
    log.RegisterHandler(log.NewLogger(log.CreateStderrLogWriter()))
    if runtime.GOOS != "linux" || os.Getenv("TERMUX_VERSION") != "" || os.Getenv("ANDROID_ROOT") != "" || strings.HasPrefix(os.Getenv("PREFIX"), "/data/data/com.termux/") { fmt.Fprintln(os.Stderr, "SS2022 relay peer requires Linux, not Android"); os.Exit(1) }
    watchdog := time.AfterFunc(lifetime+3*time.Second, func() { fmt.Fprintln(os.Stderr, "SS2022 relay peer watchdog expired"); os.Exit(1) })
    defer watchdog.Stop()
    mode := flag.String("mode", "endpoint", "endpoint, relay or client")
    method := flag.String("method", ss.MethodAES128GCM, "AES128/AES256")
    role := flag.String("role", "single", "single/multi final endpoint")
    address := flag.String("address", "127.0.0.1:0", "listen address or client peer")
    next := flag.String("next", "", "relay next hop")
    layer := flag.Int("layer", 0, "relay layer 0/1; endpoint layer 2")
    flag.Parse()
    if flag.NArg() != 0 { fmt.Fprintln(os.Stderr, "unexpected positional arguments"); os.Exit(1) }
    ctx, cancel := context.WithTimeout(context.Background(), lifetime)
    defer cancel()
    err := run(ctx, *mode, *method, *role, *address, *next, *layer)
    if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}
func run(ctx context.Context, mode, method, role, address, next string, layer int) error {
    if mode != "client" && mode != "relay" && mode != "endpoint" { return fmt.Errorf("invalid mode") }
    if (mode == "relay" && (layer < 0 || layer > 1 || next == "")) || (mode == "endpoint" && layer != 2) || (mode == "client" && layer != 0) || (mode != "relay" && next != "") { return fmt.Errorf("invalid layer/next options") }
    s, err := newScenario(method, role)
    if err != nil { return err }
    endpoint, err := resolve(address, mode == "client")
    if err != nil { return err }
    var nextHop *net.UDPAddr
    if mode == "relay" { nextHop, err = resolve(next, true); if err != nil { return err } }
    instance, err := core.NewWithContext(ctx, &core.Config{})
    if err != nil { return err }
    defer instance.Close()
    if err := instance.Start(); err != nil { return err }
    r := &reporter{mode: mode, layer: layer, s: s}
    if mode == "client" { return connect(ctx, instance, r, endpoint) }
    return serve(ctx, instance, r, endpoint, nextHop)
}
