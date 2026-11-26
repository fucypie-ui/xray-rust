// Linux live peer for the exact Xray-core pin. Production core constructors and
// Client/Server.Process own all classic cryptography and wire/session handling.
// Only the Go-client empty UDP cases use exported UDPWriter/UDPReader directly:
// the pinned generic buf.Copy used by Client.Process drops empty MultiBuffers.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
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
	ss "github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

const reference = "67756b3674d56b72c7a7e675e8dcd3f883e1b2f7"
const password = "classic-live-password"
const email, level = "classic-live@example.invalid", 7
const tcpCount, udpCount, greetingSize = 3, 6, 16

var handlerCases = []int{1, 2, 3, 4}
var emptyCases = []int{0, 5}

type scenario struct {
	method string
	network xnet.Network
	cipher ss.CipherType
	reject bool
}

func main() {
	log.RegisterHandler(log.NewLogger(log.CreateStderrLogWriter()))
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "the pinned classic peer must run on Linux")
		os.Exit(1)
	}
	watchdog := time.AfterFunc(35*time.Second, func() {
		fmt.Fprintln(os.Stderr, "classic Go peer exceeded its 35s deadline")
		os.Exit(1)
	})
	defer watchdog.Stop()
	mode := flag.String("mode", "server", "server or client")
	address := flag.String("address", "127.0.0.1:0", "loopback listen or remote endpoint")
	method := flag.String("method", "aes-128-gcm", "classic AEAD method")
	network := flag.String("network", "tcp", "tcp or udp")
	reject := flag.Bool("expect-rejected", false, "one wrong-password TCP attempt; require rejection")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(1)
	}
	if err := run(ctx, *mode, *address, *method, *network, *reject); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, mode, address, method, network string, reject bool) error {
	if mode != "server" && mode != "client" { return fmt.Errorf("unsupported mode %q", mode) }
	s := scenario{method: method, reject: reject}
	switch method {
	case "aes-128-gcm": s.cipher = ss.CipherType_AES_128_GCM
	case "aes-256-gcm": s.cipher = ss.CipherType_AES_256_GCM
	case "chacha20-ietf-poly1305": s.cipher = ss.CipherType_CHACHA20_POLY1305
	case "xchacha20-ietf-poly1305": s.cipher = ss.CipherType_XCHACHA20_POLY1305
	default: return fmt.Errorf("unsupported classic method %q", method)
	}
	switch network {
	case "tcp": s.network = xnet.Network_TCP
	case "udp": s.network = xnet.Network_UDP
	default: return fmt.Errorf("unsupported network %q", network)
	}
	if reject && s.network != xnet.Network_TCP { return fmt.Errorf("negative mode supports only TCP") }
	host, port, err := net.SplitHostPort(address)
	if err != nil { return err }
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || !ip.IsLoopback() { return fmt.Errorf("expected an IPv4 loopback endpoint") }
	endpoint, err := xnet.ParseDestination(network + ":" + net.JoinHostPort(host, port))
	if err != nil { return err }
	if mode == "client" && endpoint.Port == 0 { return fmt.Errorf("remote port must be nonzero") }
	instance, err := core.NewWithContext(ctx, &core.Config{})
	if err != nil { return err }
	defer instance.Close()
	if err := instance.Start(); err != nil { return err }
	if mode == "server" { return serve(ctx, instance, endpoint, s) }
	return connect(ctx, instance, endpoint, s)
}

func (s scenario) user() *protocol.User {
	return &protocol.User{Email: email, Level: level, Account: serial.ToTypedMessage(&ss.Account{Password: password, CipherType: s.cipher})}
}

func destination(index int, reply bool, network xnet.Network) xnet.Destination {
	values := []string{
		"empty.example.invalid:443", "203.0.113.7:5353", "[2001:db8::7]:9000",
		"large.example.invalid:8443", "198.51.100.8:9001", "[2001:db8::8]:5353",
	}
	if reply { values = []string{
		"[2001:db8::50]:9443", "198.51.100.70:5354", "response.example.invalid:9002",
		"[2001:db8::51]:8444", "last.example.invalid:9003", "empty-reply.example.invalid:5354",
	} }
	value, err := xnet.ParseDestination(network.SystemString() + ":" + values[index])
	if err != nil { panic(err) }
	return value
}

func payload(index int, reply bool, network xnet.Network) []byte {
	sizes, salt := []int{0, 1, 257, 7900, 19, 0}, 0x31
	if reply { sizes, salt = []int{0, 19, 513, 7800, 1, 0}, 0xa7 }
	if network == xnet.Network_TCP {
		sizes = []int{1, 16641, 50000}
		if reply { sizes = []int{257, 17000, 49000} }
	}
	result := make([]byte, sizes[index])
	for i := range result { result[i] = byte(i*73 + i/251 + salt + index*17) }
	return result
}

func sameDestination(a, b xnet.Destination) bool {
	return a.Network == b.Network && a.Port == b.Port && a.Address.String() == b.Address.String()
}

func packet(index int, reply bool) *buf.Buffer {
	b := buf.FromBytes(payload(index, reply, xnet.Network_UDP))
	target := destination(index, reply, xnet.Network_UDP)
	b.UDP = &target
	return b
}

func checkPacket(index int, reply bool, b *buf.Buffer) error {
	if b == nil || b.UDP == nil || !sameDestination(*b.UDP, destination(index, reply, xnet.Network_UDP)) ||
		!bytes.Equal(b.Bytes(), payload(index, reply, xnet.Network_UDP)) {
		return fmt.Errorf("UDP %d reply=%t: exact payload/source-address mismatch", index, reply)
	}
	return nil
}

func report(event, mode, path string, s scenario, local, remote net.Addr, exchanges, sessions int) error {
	peer := ""
	if remote != nil { peer = remote.String() }
	return json.NewEncoder(os.Stdout).Encode(struct {
		Event string `json:"event"`
		Source string `json:"source"`
		Mode string `json:"mode"`
		Network string `json:"network"`
		Method string `json:"method"`
		Path string `json:"path"`
		Address string `json:"address"`
		Peer string `json:"peer"`
		Exchanges int `json:"exchanges"`
		Sessions int `json:"sessions"`
	}{event, reference, mode, s.network.SystemString(), s.method, path, local.String(), peer, exchanges, sessions})
}

func waitExit() error {
	line, err := bufio.NewReader(io.LimitReader(os.Stdin, 16)).ReadString('\n')
	if err != nil || line != "exit\n" { return fmt.Errorf("expected exit control line, got %q: %v", line, err) }
	return nil
}

func checkClosed(conn net.Conn) error {
	if n, err := conn.Write([]byte{0xff}); n != 0 || !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("write after socket close: n=%d err=%v", n, err)
	}
	if socket, ok := conn.(*net.UDPConn); ok {
		probe, err := net.ListenUDP("udp4", socket.LocalAddr().(*net.UDPAddr))
		if err != nil { return fmt.Errorf("UDP socket not released: %w", err) }
		return probe.Close()
	}
	return nil
}

// Application-side link: bounded exact byte streams, no protocol processing.
// The first 16 response bytes precede the request to check eager target headers.
// Remaining response bytes become readable only after exact request validation.
type tcpLink struct {
	ctx context.Context
	index int
	data []byte
	validated chan struct{}
	reads int
}

func (l *tcpLink) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	expected := payload(l.index, false, xnet.Network_TCP)
	for _, b := range mb {
		if len(l.data)+int(b.Len()) > len(expected) { return fmt.Errorf("extra TCP request bytes") }
		l.data = append(l.data, b.Bytes()...)
	}
	if !bytes.Equal(l.data, expected[:len(l.data)]) { return fmt.Errorf("TCP binary request mismatch") }
	if len(l.data) == len(expected) {
		select { case <-l.validated: default: close(l.validated) }
	}
	return nil
}

func (l *tcpLink) ReadMultiBuffer() (buf.MultiBuffer, error) {
	response := payload(l.index, true, xnet.Network_TCP)
	l.reads++
	if l.reads == 1 { return buf.MergeBytes(nil, response[:greetingSize]), nil }
	if l.reads > 2 { return nil, io.EOF }
	select {
	case <-l.validated: return buf.MergeBytes(nil, response[greetingSize:]), nil
	case <-l.ctx.Done(): return nil, l.ctx.Err()
	}
}

func (l *tcpLink) Close() error {
	if !bytes.Equal(l.data, payload(l.index, false, xnet.Network_TCP)) {
		return fmt.Errorf("TCP request closed before its complete exact payload")
	}
	return nil
}

type udpLink struct {
	ctx context.Context
	responses chan buf.MultiBuffer
	failures chan error
	index int
}

func (l *udpLink) ReadMultiBuffer() (buf.MultiBuffer, error) {
	select {
	case response := <-l.responses: return response, nil
	case <-l.ctx.Done(): return nil, l.ctx.Err()
	}
}

func (l *udpLink) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		err := fmt.Errorf("unexpected additional UDP request")
		if l.index < udpCount { err = checkPacket(l.index, false, b) }
		if err != nil {
			select { case l.failures <- err: default: }
			return err
		}
		response := buf.MultiBuffer{packet(l.index, true)}
		l.index++
		select {
		case l.responses <- response:
		case <-l.ctx.Done(): buf.ReleaseMulti(response); return l.ctx.Err()
		}
	}
	return nil
}

type dispatcher struct {
	expected xnet.Destination
	source xnet.Destination
	link *transport.Link
	calls int
}

func (*dispatcher) Type() interface{} { return routing.DispatcherType() }
func (*dispatcher) Start() error { return nil }
func (*dispatcher) Close() error { return nil }
func (*dispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error { return fmt.Errorf("unexpected DispatchLink") }
func (d *dispatcher) Dispatch(ctx context.Context, target xnet.Destination) (*transport.Link, error) {
	d.calls++
	inbound := session.InboundFromContext(ctx)
	if d.calls != 1 || !sameDestination(target, d.expected) || inbound == nil || inbound.User == nil ||
		inbound.User.Email != email || inbound.User.Level != level || !sameDestination(inbound.Source, d.source) {
		return nil, fmt.Errorf("production Go dispatch target/source/user mismatch")
	}
	return d.link, nil
}

func processContext(ctx context.Context, local, remote net.Addr) context.Context {
	return session.ContextWithInbound(ctx, &session.Inbound{
		Source: xnet.DestinationFromAddr(remote), Local: xnet.DestinationFromAddr(local), Tag: "go-live",
	})
}

func serve(ctx context.Context, instance *core.Instance, endpoint xnet.Destination, s scenario) error {
	object, err := core.CreateObject(instance, &ss.ServerConfig{Users: []*protocol.User{s.user()}, Network: []xnet.Network{s.network}})
	if err != nil { return err }
	inbound := object.(proxy.Inbound)
	if s.network == xnet.Network_UDP { return serveUDP(ctx, inbound, endpoint, s) }
	listener, err := net.ListenTCP("tcp4", endpoint.RawNetAddr().(*net.TCPAddr))
	if err != nil { return err }
	defer listener.Close()
	deadline, _ := ctx.Deadline()
	if err := listener.SetDeadline(deadline); err != nil { return err }
	if err := report("ready", "server", "handler", s, listener.Addr(), nil, 0, 0); err != nil { return err }
	if s.reject { return rejectInbound(ctx, inbound, listener, s) }
	var remote net.Addr
	for index := 0; index < tcpCount; index++ {
		socket, err := listener.AcceptTCP()
		if err != nil { return err }
		remote = socket.RemoteAddr()
		if err := socket.SetDeadline(deadline); err != nil { socket.Close(); return err }
		processCtx, cancel := context.WithCancel(ctx)
		link := &tcpLink{ctx: processCtx, index: index, validated: make(chan struct{})}
		dispatch := &dispatcher{expected: destination(index, false, s.network), source: xnet.DestinationFromAddr(remote), link: &transport.Link{Reader: link, Writer: link}}
		err = inbound.Process(processContext(processCtx, socket.LocalAddr(), remote), s.network, socket, dispatch)
		cancel()
		closeErr := socket.Close()
		if err != nil { return err }
		if closeErr != nil { return closeErr }
		if err := checkClosed(socket); err != nil { return err }
		if err := link.Close(); err != nil { return err }
		if dispatch.calls != 1 { return fmt.Errorf("missing TCP dispatch") }
		if err := report("session_complete", "server", "handler", s, listener.Addr(), remote, index+1, index+1); err != nil { return err }
	}
	if err := report("complete", "server", "handler", s, listener.Addr(), remote, tcpCount, tcpCount); err != nil { return err }
	if err := waitExit(); err != nil { return err }
	local := listener.Addr()
	if err := listener.Close(); err != nil { return err }
	probe, err := net.ListenTCP("tcp4", local.(*net.TCPAddr))
	if err != nil { return fmt.Errorf("TCP listener not released: %w", err) }
	if err := probe.Close(); err != nil { return err }
	return report("closed", "server", "handler", s, local, remote, tcpCount, tcpCount)
}

// Raw socket adapter for the production per-peer inbound Process boundary.
// No Shadowsocks parsing, encryption, authentication or key handling here.
type peerConn struct {
	*net.UDPConn
	remote *net.UDPAddr
	first []byte
	writes int
	complete chan struct{}
}

func readWire(socket *net.UDPConn) ([]byte, *net.UDPAddr, error) {
	var wire [buf.Size + 1]byte
	n, remote, err := socket.ReadFromUDP(wire[:])
	if err != nil { return nil, nil, err }
	if n > buf.Size { return nil, nil, fmt.Errorf("oversize encrypted UDP packet") }
	return append([]byte(nil), wire[:n]...), remote, nil
}

func (c *peerConn) RemoteAddr() net.Addr { return c.remote }
func (c *peerConn) Read(output []byte) (int, error) {
	wire := c.first
	c.first = nil
	if wire == nil {
		var remote *net.UDPAddr
		var err error
		wire, remote, err = readWire(c.UDPConn)
		if err != nil { return 0, err }
		if remote.String() != c.remote.String() { return 0, fmt.Errorf("unexpected additional UDP peer") }
	}
	if len(wire) > len(output) { return 0, io.ErrShortBuffer }
	return copy(output, wire), nil
}
func (c *peerConn) Write(wire []byte) (int, error) {
	n, err := c.WriteToUDP(wire, c.remote)
	if err == nil && n != len(wire) { err = io.ErrShortWrite }
	if err == nil {
		c.writes++
		if c.writes == udpCount { close(c.complete) }
	}
	return n, err
}

func serveUDP(ctx context.Context, inbound proxy.Inbound, endpoint xnet.Destination, s scenario) error {
	socket, err := net.ListenUDP("udp4", endpoint.RawNetAddr().(*net.UDPAddr))
	if err != nil { return err }
	defer socket.Close()
	deadline, _ := ctx.Deadline()
	if err := socket.SetDeadline(deadline); err != nil { return err }
	if err := report("ready", "server", "handler", s, socket.LocalAddr(), nil, 0, 0); err != nil { return err }
	wire, remote, err := readWire(socket)
	if err != nil { return err }
	conn := &peerConn{UDPConn: socket, remote: remote, first: wire, complete: make(chan struct{})}
	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	link := &udpLink{ctx: processCtx, responses: make(chan buf.MultiBuffer, udpCount), failures: make(chan error, 1)}
	dispatch := &dispatcher{expected: destination(0, false, s.network), source: xnet.DestinationFromAddr(remote), link: &transport.Link{Reader: link, Writer: link}}
	finished := make(chan error, 1)
	go func() { finished <- inbound.Process(processContext(processCtx, socket.LocalAddr(), remote), s.network, conn, dispatch) }()
	select {
	case <-conn.complete:
	case err := <-link.failures: return err
	case err := <-finished: return fmt.Errorf("Go UDP inbound ended early: %v", err)
	case <-ctx.Done(): return ctx.Err()
	}
	if link.index != udpCount || dispatch.calls != 1 { return fmt.Errorf("incomplete production UDP dispatch") }
	if err := report("complete", "server", "handler", s, socket.LocalAddr(), remote, udpCount, 1); err != nil { return err }
	if err := waitExit(); err != nil { return err }
	cancel()
	if err := socket.Close(); err != nil { return err }
	select {
	case err := <-finished:
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) { return err }
	case <-ctx.Done(): return ctx.Err()
	}
	if err := checkClosed(socket); err != nil { return err }
	return report("closed", "server", "handler", s, socket.LocalAddr(), remote, udpCount, 1)
}

type socketDialer struct {
	remote xnet.Destination
	dialed chan net.Conn
}
func (*socketDialer) DestIpAddress() xnet.IP { return xnet.LocalHostIP.IP() }
func (*socketDialer) SetOutboundGateway(context.Context, *session.Outbound) {}
func (d *socketDialer) Dial(ctx context.Context, target xnet.Destination) (stat.Connection, error) {
	if !sameDestination(target, d.remote) { return nil, fmt.Errorf("Go client did not select the requested server/network") }
	var dialer net.Dialer
	socket, err := dialer.DialContext(ctx, target.Network.SystemString()+"4", target.NetAddr())
	if err != nil { return nil, err }
	deadline, _ := ctx.Deadline()
	if err := socket.SetDeadline(deadline); err != nil { socket.Close(); return nil, err }
	select {
	case d.dialed <- socket: return socket, nil
	case <-ctx.Done(): socket.Close(); return nil, ctx.Err()
	}
}

func awaitDial(ctx context.Context, dialer *socketDialer, finished chan error) (net.Conn, error) {
	select {
	case socket := <-dialer.dialed: return socket, nil
	case err := <-finished:
		// A quick rejection can finish Process before this goroutine runs.
		// Prefer the already-recorded dial and preserve its completion result.
		select {
		case socket := <-dialer.dialed:
			finished <- err // one producer, one-slot completion channel
			return socket, nil
		default: return nil, fmt.Errorf("Go Client.Process ended before dial: %v", err)
		}
	case <-ctx.Done(): return nil, ctx.Err()
	}
}

type byteSink struct { data []byte; limit int }
func (b *byteSink) Write(value []byte) (int, error) {
	if len(b.data)+len(value) > b.limit { return 0, fmt.Errorf("excess TCP reply bytes") }
	b.data = append(b.data, value...)
	return len(value), nil
}

func connect(ctx context.Context, instance *core.Instance, remote xnet.Destination, s scenario) error {
	object, err := core.CreateObject(instance, &ss.ClientConfig{Server: &protocol.ServerEndpoint{
		Address: xnet.NewIPOrDomain(remote.Address), Port: uint32(remote.Port), User: s.user(),
	}})
	if err != nil { return err }
	outbound := object.(proxy.Outbound)
	if s.network == xnet.Network_UDP { return connectUDP(ctx, outbound, remote, s) }
	if s.reject { return rejectOutbound(ctx, outbound, remote, s) }
	var local net.Addr
	for index := 0; index < tcpCount; index++ {
		processCtx, cancel := context.WithCancel(ctx)
		processCtx = session.ContextWithOutbounds(processCtx, []*session.Outbound{{Target: destination(index, false, s.network)}})
		requests, writer := pipe.New(pipe.WithSizeLimit(65536))
		if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, payload(index, false, s.network))); err != nil { cancel(); return err }
		if err := writer.Close(); err != nil { cancel(); return err }
		sink := &byteSink{limit: len(payload(index, true, s.network))}
		dialer := &socketDialer{remote: remote, dialed: make(chan net.Conn, 1)}
		finished := make(chan error, 1)
		go func() { finished <- outbound.Process(processCtx, &transport.Link{Reader: requests, Writer: buf.NewWriter(sink)}, dialer) }()
		socket, err := awaitDial(ctx, dialer, finished)
		if err != nil { cancel(); requests.Interrupt(); return err }
		local = socket.LocalAddr()
		if index == 0 {
			if err := report("ready", "client", "handler", s, local, socket.RemoteAddr(), 0, 1); err != nil { cancel(); socket.Close(); return err }
		}
		select {
		case err = <-finished:
		case <-ctx.Done(): err = ctx.Err()
		}
		cancel()
		requests.Interrupt()
		socket.Close()
		if err != nil { return err }
		if !bytes.Equal(sink.data, payload(index, true, s.network)) { return fmt.Errorf("Go TCP response binary mismatch") }
		if err := checkClosed(socket); err != nil { return err }
		if err := report("session_complete", "client", "handler", s, local, socket.RemoteAddr(), index+1, index+1); err != nil { return err }
	}
	if err := report("complete", "client", "handler", s, local, remote.RawNetAddr(), tcpCount, tcpCount); err != nil { return err }
	if err := waitExit(); err != nil { return err }
	return report("closed", "client", "handler", s, local, remote.RawNetAddr(), tcpCount, tcpCount)
}

type replyCollector struct { index int; results chan error }
func (c *replyCollector) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		err := fmt.Errorf("unexpected additional Go UDP reply")
		if c.index < 5 { err = checkPacket(c.index, true, b) }
		c.index++
		select { case c.results <- err: default: return fmt.Errorf("UDP result queue overflow") }
		if err != nil { return err }
	}
	return nil
}

func connectUDP(ctx context.Context, outbound proxy.Outbound, remote xnet.Destination, s scenario) error {
	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	processCtx = session.ContextWithOutbounds(processCtx, []*session.Outbound{{Target: destination(1, false, s.network)}})
	requests, writer := pipe.New(pipe.WithSizeLimit(16384))
	defer writer.Close()
	defer requests.Interrupt()
	collector := &replyCollector{index: 1, results: make(chan error, udpCount)}
	dialer := &socketDialer{remote: remote, dialed: make(chan net.Conn, 1)}
	finished := make(chan error, 1)
	go func() { finished <- outbound.Process(processCtx, &transport.Link{Reader: requests, Writer: collector}, dialer) }()
	socket, err := awaitDial(ctx, dialer, finished)
	if err != nil { return err }
	defer socket.Close()
	if err := report("ready", "client", "handler", s, socket.LocalAddr(), socket.RemoteAddr(), 0, 1); err != nil { return err }
	for _, index := range handlerCases {
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{packet(index, false)}); err != nil { return err }
		select {
		case err := <-collector.results: if err != nil { return err }
		case err := <-finished: return fmt.Errorf("UDP client ended before reply %d: %v", index, err)
		case <-ctx.Done(): return ctx.Err()
		}
	}
	if err := report("handler_complete", "client", "handler", s, socket.LocalAddr(), socket.RemoteAddr(), len(handlerCases), 1); err != nil { return err }
	cancel()
	// Process may return on context cancellation before its request goroutine.
	// Unblock that goroutine as part of closing the owned transport.
	if err := writer.Close(); err != nil { return err }
	if err := socket.Close(); err != nil && !errors.Is(err, net.ErrClosed) { return err }
	select {
	case err := <-finished:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) { return err }
	case <-ctx.Done(): return ctx.Err()
	}
	if err := checkClosed(socket); err != nil { return err }
	if err := report("handler_closed", "client", "handler", s, socket.LocalAddr(), socket.RemoteAddr(), len(handlerCases), 1); err != nil { return err }

	// Reserve the released old local port while choosing the second socket,
	// so native source-keyed flows cannot accidentally reuse the first peer.
	reservation, err := net.ListenUDP("udp4", socket.LocalAddr().(*net.UDPAddr))
	if err != nil { return err }
	emptySocket, err := net.DialUDP("udp4", nil, remote.RawNetAddr().(*net.UDPAddr))
	reservation.Close()
	if err != nil { return err }
	defer emptySocket.Close()
	deadline, _ := ctx.Deadline()
	if err := emptySocket.SetDeadline(deadline); err != nil { return err }
	if err := report("empty_ready", "client", "session", s, emptySocket.LocalAddr(), emptySocket.RemoteAddr(), 0, 1); err != nil { return err }
	user, err := s.user().ToMemoryUser()
	if err != nil { return err }
	udpWriter := &ss.UDPWriter{Writer: emptySocket, Request: &protocol.RequestHeader{
		Version: ss.Version, Command: protocol.RequestCommandUDP, User: user,
		Address: destination(0, false, s.network).Address, Port: destination(0, false, s.network).Port,
	}}
	udpReader := &ss.UDPReader{Reader: emptySocket, User: user}
	for _, index := range emptyCases {
		if err := udpWriter.WriteMultiBuffer(buf.MultiBuffer{packet(index, false)}); err != nil { return err }
		mb, err := udpReader.ReadMultiBuffer()
		if err != nil { buf.ReleaseMulti(mb); return err }
		if len(mb) != 1 { buf.ReleaseMulti(mb); return fmt.Errorf("expected one empty UDP reply, not EOF") }
		err = checkPacket(index, true, mb[0])
		buf.ReleaseMulti(mb)
		if err != nil { return err }
	}
	if err := emptySocket.Close(); err != nil { return err }
	if err := checkClosed(emptySocket); err != nil { return err }
	if err := report("complete", "client", "handler+session", s, emptySocket.LocalAddr(), emptySocket.RemoteAddr(), udpCount, 2); err != nil { return err }
	if err := waitExit(); err != nil { return err }
	return report("closed", "client", "handler+session", s, emptySocket.LocalAddr(), emptySocket.RemoteAddr(), udpCount, 2)
}

// These negatives still execute the real handlers. The Rust side uses the
// deliberately different password; no malformed packet or local crypto is used.
func rejectInbound(ctx context.Context, inbound proxy.Inbound, listener *net.TCPListener, s scenario) error {
	socket, err := listener.AcceptTCP()
	if err != nil { return err }
	defer socket.Close()
	deadline, _ := ctx.Deadline()
	if err := socket.SetDeadline(deadline); err != nil { return err }
	link := &tcpLink{ctx: ctx, validated: make(chan struct{})}
	dispatch := &dispatcher{expected: destination(0, false, s.network), source: xnet.DestinationFromAddr(socket.RemoteAddr()), link: &transport.Link{Reader: link, Writer: link}}
	err = inbound.Process(processContext(ctx, socket.LocalAddr(), socket.RemoteAddr()), s.network, socket, dispatch)
	if !errors.Is(err, ss.ErrNotFound) || ctx.Err() != nil || dispatch.calls != 0 {
		return fmt.Errorf("expected production wrong-password user rejection before dispatch: %v", err)
	}
	fmt.Fprintln(os.Stderr, "expected Go Server.Process authentication rejection:", err)
	if err := socket.Close(); err != nil { return err }
	if err := checkClosed(socket); err != nil { return err }
	if err := report("rejected", "server", "handler", s, listener.Addr(), socket.RemoteAddr(), 0, 1); err != nil { return err }
	if err := waitExit(); err != nil { return err }
	local := listener.Addr()
	if err := listener.Close(); err != nil { return err }
	probe, err := net.ListenTCP("tcp4", local.(*net.TCPAddr))
	if err != nil { return fmt.Errorf("negative TCP listener not released: %w", err) }
	if err := probe.Close(); err != nil { return err }
	return report("closed", "server", "handler", s, local, socket.RemoteAddr(), 0, 1)
}

func rejectOutbound(ctx context.Context, outbound proxy.Outbound, remote xnet.Destination, s scenario) error {
	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	processCtx = session.ContextWithOutbounds(processCtx, []*session.Outbound{{Target: destination(0, false, s.network)}})
	requests, writer := pipe.New(pipe.WithSizeLimit(8192))
	defer requests.Interrupt()
	// More than the pinned Go probing drain upper bound, still strictly bounded.
	if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, bytes.Repeat([]byte{0x99}, 4096))); err != nil { return err }
	if err := writer.Close(); err != nil { return err }
	sink := &byteSink{limit: 1}
	dialer := &socketDialer{remote: remote, dialed: make(chan net.Conn, 1)}
	finished := make(chan error, 1)
	go func() { finished <- outbound.Process(processCtx, &transport.Link{Reader: requests, Writer: buf.NewWriter(sink)}, dialer) }()
	socket, err := awaitDial(ctx, dialer, finished)
	if err != nil { return err }
	defer socket.Close()
	if err := report("ready", "client", "handler", s, socket.LocalAddr(), socket.RemoteAddr(), 0, 1); err != nil { return err }
	select {
	case err := <-finished:
		if err == nil || ctx.Err() != nil || len(sink.data) != 0 { return fmt.Errorf("expected Go Client.Process rejection with no plaintext: %v", err) }
		fmt.Fprintln(os.Stderr, "expected Go Client.Process authentication rejection:", err)
	case <-ctx.Done(): return ctx.Err()
	}
	cancel()
	socket.Close()
	if err := checkClosed(socket); err != nil { return err }
	if err := report("rejected", "client", "handler", s, socket.LocalAddr(), socket.RemoteAddr(), 0, 1); err != nil { return err }
	if err := waitExit(); err != nil { return err }
	return report("closed", "client", "handler", s, socket.LocalAddr(), socket.RemoteAddr(), 0, 1)
}
