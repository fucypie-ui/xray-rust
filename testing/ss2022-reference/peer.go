// Live SS2022 peer built inside the exact pinned module by build-peer.sh.
// Crypto, EIH, replay, and session handling belong entirely to production Go.
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
	"strings"
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
const email, level = "live-user@example.invalid", 7
const packetCount = 6

type scenario struct {
	method, role string
	keys [][]byte
}

func main() {
	// Reserve stdout for JSON before any constructors or network activity.
	log.RegisterHandler(log.NewLogger(log.CreateStderrLogWriter()))
	watchdog := time.AfterFunc(25*time.Second, func() {
		fmt.Fprintln(os.Stderr, "live Go SS2022 peer exceeded 25s deadline")
		os.Exit(1)
	})
	defer watchdog.Stop()
	mode := flag.String("mode", "server", "server or client")
	address := flag.String("address", "127.0.0.1:0", "UDP listen or remote address")
	method := flag.String("method", ss.MethodAES128GCM, "SS2022 cipher method")
	role := flag.String("role", "single", "single or multi (AES EIH)")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := run(ctx, *mode, *address, *method, *role); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, mode, address, method, role string) error {
	if mode != "server" && mode != "client" { return fmt.Errorf("expected server/client mode") }
	s := scenario{method: method, role: role}
	size := 32
	switch method {
	case ss.MethodAES128GCM: size = 16
	case ss.MethodAES256GCM, ss.MethodChaCha20Poly1305:
	default: return fmt.Errorf("unsupported method %q", method)
	}
	if role != "single" && role != "multi" { return fmt.Errorf("unsupported role %q", role) }
	if role == "multi" && method == ss.MethodChaCha20Poly1305 { return fmt.Errorf("ChaCha multi-user is unsupported") }
	if role == "multi" { s.keys = append(s.keys, key(size, 0xa1)) }
	s.keys = append(s.keys, key(size, 0x11))
	endpoint, err := net.ResolveUDPAddr("udp4", address)
	if err != nil { return err }
	if !endpoint.IP.IsLoopback() || (mode == "client" && endpoint.Port == 0) { return fmt.Errorf("expected a loopback UDP endpoint") }
	instance, err := core.NewWithContext(ctx, &core.Config{})
	if err != nil { return err }
	defer instance.Close()
	if err := instance.Start(); err != nil { return err }
	if mode == "server" { return serve(ctx, instance, endpoint, s) }
	return connect(ctx, instance, endpoint, s)
}

func key(size int, first byte) []byte {
	value := make([]byte, size)
	for i := range value { value[i] = first + byte(i) }
	return value
}

func (s scenario) encodedKeys() string {
	parts := make([]string, len(s.keys))
	for i, value := range s.keys { parts[i] = base64.StdEncoding.EncodeToString(value) }
	return strings.Join(parts, ":")
}

// Deliberately different response addresses/payloads catch echo-only and
// destination-as-reply-source adapters. None of these targets is DNS-resolved.
func destination(index int, reply bool) xnet.Destination {
	addresses := []string{
		"empty.example.invalid:443", "203.0.113.7:5353", "[2001:db8::7]:9000",
		"large.example.invalid:8443", "198.51.100.8:9001", "[2001:db8::8]:5353",
	}
	if reply { addresses = []string{
		"[2001:db8::50]:9443", "198.51.100.70:5354", "response.example.invalid:9002",
		"[2001:db8::51]:8444", "last.example.invalid:9003", "empty-reply.example.invalid:5354",
	} }
	value, err := xnet.ParseDestination("udp:" + addresses[index])
	if err != nil { panic(err) }
	return value
}

func payload(index int, reply bool) []byte {
	sizes, salt := []int{0, 1, 257, 7900, 19, 0}, 0x31
	if reply { sizes, salt = []int{0, 19, 513, 7800, 1, 0}, 0xa7 }
	value := make([]byte, sizes[index])
	for i := range value { value[i] = byte(i*73 + i/251 + salt + index*17) }
	return value
}

func sameDestination(a, b xnet.Destination) bool {
	return a.Network == b.Network && a.Port == b.Port && a.Address.String() == b.Address.String()
}

func packet(index int, reply bool) *buf.Buffer {
	b := buf.FromBytes(payload(index, reply))
	dest := destination(index, reply)
	b.UDP = &dest
	return b
}

func checkPacket(index int, reply bool, b *buf.Buffer) error {
	if b == nil || b.UDP == nil || !sameDestination(*b.UDP, destination(index, reply)) || !bytes.Equal(b.Bytes(), payload(index, reply)) {
		return fmt.Errorf("packet %d reply=%t: exact binary payload/address mismatch", index, reply)
	}
	return nil
}

func report(kind, mode, path string, s scenario, address, peer net.Addr, packets, sessions int) error {
	remote := ""
	if peer != nil { remote = peer.String() }
	return json.NewEncoder(os.Stdout).Encode(struct {
		Event string `json:"event"`
		Source string `json:"source"`
		Mode string `json:"mode"`
		Method string `json:"method"`
		Role string `json:"role"`
		Path string `json:"path"`
		Address string `json:"address"`
		Peer string `json:"peer"`
		Packets int `json:"packets"`
		Sessions int `json:"sessions"`
	}{kind, reference, mode, s.method, s.role, path, address.String(), remote, packets, sessions})
}

func waitExit() error {
	line, err := bufio.NewReader(io.LimitReader(os.Stdin, 16)).ReadString('\n')
	if err != nil || line != "exit\n" { return fmt.Errorf("expected exit control line, got %q: %v", line, err) }
	return nil
}

func checkClosed(socket *net.UDPConn) error {
	if n, err := socket.Write([]byte{0xff}); n != 0 || !errors.Is(err, net.ErrClosed) { return fmt.Errorf("write after close: n=%d err=%v", n, err) }
	probe, err := net.ListenUDP("udp4", socket.LocalAddr().(*net.UDPAddr))
	if err != nil { return fmt.Errorf("socket not released: %w", err) }
	return probe.Close()
}

// Only adapts a real UDP socket to Process's per-peer stat.Connection contract.
// It neither reads nor writes SS2022 headers. Reject any truncation or new peer.
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
	if n > buf.Size { return nil, nil, fmt.Errorf("oversize encrypted packet") }
	return append([]byte(nil), wire[:n]...), remote, nil
}

func (c *peerConn) Read(output []byte) (int, error) {
	wire := c.first
	c.first = nil
	if wire == nil {
		var remote *net.UDPAddr
		var err error
		wire, remote, err = readWire(c.UDPConn)
		if err != nil { return 0, err }
		if remote.String() != c.remote.String() { return 0, fmt.Errorf("unexpected UDP peer %s", remote) }
	}
	if len(wire) > len(output) { return 0, io.ErrShortBuffer }
	return copy(output, wire), nil
}

func (c *peerConn) RemoteAddr() net.Addr { return c.remote }
func (c *peerConn) Write(wire []byte) (int, error) {
	n, err := c.WriteToUDP(wire, c.remote)
	if err == nil && n != len(wire) { err = io.ErrShortWrite }
	if err == nil {
		c.writes++
		if c.writes == packetCount { close(c.complete) }
	}
	return n, err
}

type echoLink struct {
	ctx context.Context
	responses chan buf.MultiBuffer
	failures chan error
	index int
}

func (e *echoLink) ReadMultiBuffer() (buf.MultiBuffer, error) {
	select {
	case mb := <-e.responses: return mb, nil
	case <-e.ctx.Done(): return nil, e.ctx.Err()
	}
}

func (e *echoLink) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		err := fmt.Errorf("unexpected additional packet")
		if e.index < packetCount { err = checkPacket(e.index, false, b) }
		if err != nil {
			select { case e.failures <- err: default: }
			return err
		}
		response := buf.MultiBuffer{packet(e.index, true)}
		e.index++
		select {
		case e.responses <- response:
		case <-e.ctx.Done(): buf.ReleaseMulti(response); return e.ctx.Err()
		}
	}
	return nil
}

type echoDispatcher struct {
	link *echoLink
	source xnet.Destination
	calls int
}

func (*echoDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*echoDispatcher) Start() error { return nil }
func (*echoDispatcher) Close() error { return nil }
func (*echoDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error { return fmt.Errorf("unexpected DispatchLink") }
func (d *echoDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	d.calls++
	inbound := session.InboundFromContext(ctx)
	if d.calls != 1 || !sameDestination(dest, destination(0, false)) || inbound == nil ||
		!sameDestination(inbound.Source, d.source) || inbound.User == nil || inbound.User.Email != email || inbound.User.Level != level {
		err := fmt.Errorf("production inbound dispatch/source/user mismatch")
		select { case d.link.failures <- err: default: }
		return nil, err
	}
	return &transport.Link{Reader: d.link, Writer: d.link}, nil
}

func serve(ctx context.Context, instance *core.Instance, endpoint *net.UDPAddr, s scenario) error {
	var config interface{} = &ss.ServerConfig{Method: s.method, Key: s.encodedKeys(), Email: email, Level: level, Network: []xnet.Network{xnet.Network_UDP}}
	if s.role == "multi" {
		users := make([]*protocol.User, 0, 2)
		for i, psk := range [][]byte{key(len(s.keys[0]), 0x51), s.keys[1]} {
			name := "decoy@example.invalid"
			if i == 1 { name = email }
			users = append(users, &protocol.User{Email: name, Level: level, Account: serial.ToTypedMessage(&ss.Account{Key: base64.StdEncoding.EncodeToString(psk)})})
		}
		config = &ss.MultiUserServerConfig{Method: s.method, Key: base64.StdEncoding.EncodeToString(s.keys[0]), Users: users, Network: []xnet.Network{xnet.Network_UDP}}
	}
	object, err := core.CreateObject(instance, config) // production NewServer/NewMultiServer
	if err != nil { return err }
	inbound := object.(proxy.Inbound)
	socket, err := net.ListenUDP("udp4", endpoint)
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
	source := xnet.DestinationFromAddr(remote)
	processCtx = session.ContextWithInbound(processCtx, &session.Inbound{Source: source, Local: xnet.DestinationFromAddr(socket.LocalAddr()), Tag: "go-live"})
	link := &echoLink{ctx: processCtx, responses: make(chan buf.MultiBuffer, packetCount), failures: make(chan error, 1)}
	dispatcher := &echoDispatcher{link: link, source: source}
	finished := make(chan error, 1)
	go func() { finished <- inbound.Process(processCtx, xnet.Network_UDP, conn, dispatcher) }()
	select {
	case <-conn.complete:
	case err := <-link.failures: return err
	case err := <-finished: return fmt.Errorf("inbound ended before all packets: %v", err)
	case <-ctx.Done(): return ctx.Err()
	}
	if link.index != packetCount || dispatcher.calls != 1 { return fmt.Errorf("incomplete production inbound session") }
	if err := report("complete", "server", "handler", s, socket.LocalAddr(), remote, packetCount, 1); err != nil { return err }
	if err := waitExit(); err != nil { return err }
	cancel()
	if err := socket.Close(); err != nil { return err }
	select {
	case err := <-finished:
		if !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) { return fmt.Errorf("inbound close: %v", err) }
	case <-ctx.Done(): return ctx.Err()
	}
	if err := checkClosed(socket); err != nil { return err }
	return report("closed", "server", "handler", s, socket.LocalAddr(), remote, packetCount, 1)
}

type udpDialer struct {
	remote *net.UDPAddr
	dialed chan *net.UDPConn
}

func (*udpDialer) DestIpAddress() xnet.IP { return xnet.LocalHostIP.IP() }
func (*udpDialer) SetOutboundGateway(context.Context, *session.Outbound) {}
func (d *udpDialer) Dial(ctx context.Context, destination xnet.Destination) (stat.Connection, error) {
	if !sameDestination(destination, xnet.DestinationFromAddr(d.remote)) { return nil, fmt.Errorf("outbound did not choose dynamic UDP transport") }
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp4", d.remote.String())
	if err != nil { return nil, err }
	socket := conn.(*net.UDPConn)
	deadline, _ := ctx.Deadline()
	if err := socket.SetDeadline(deadline); err != nil { socket.Close(); return nil, err }
	select {
	case d.dialed <- socket: return socket, nil
	case <-ctx.Done(): socket.Close(); return nil, ctx.Err()
	}
}

type replyCollector struct {
	index int
	results chan error
}

func (c *replyCollector) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		err := fmt.Errorf("unexpected additional reply")
		if c.index < 5 { err = checkPacket(c.index, true, b) }
		c.index++
		select { case c.results <- err: default: return fmt.Errorf("unexpected reply count") }
		if err != nil { return err }
	}
	return nil
}

func connect(ctx context.Context, instance *core.Instance, remote *net.UDPAddr, s scenario) error {
	object, err := core.CreateObject(instance, &ss.ClientConfig{
		Method: s.method, Key: s.encodedKeys(), Address: xnet.NewIPOrDomain(xnet.IPAddress(remote.IP)), Port: uint32(remote.Port),
	}) // production NewClient, then its full outbound Process path
	if err != nil { return err }
	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	processCtx = session.ContextWithOutbounds(processCtx, []*session.Outbound{{Target: destination(1, false)}})
	requests, writer := pipe.New()
	defer writer.Close()
	defer requests.Interrupt()
	collector := &replyCollector{index: 1, results: make(chan error, packetCount)}
	dialer := &udpDialer{remote: remote, dialed: make(chan *net.UDPConn, 1)}
	finished := make(chan error, 1)
	go func() { finished <- object.(proxy.Outbound).Process(processCtx, &transport.Link{Reader: requests, Writer: collector}, dialer) }()
	var socket *net.UDPConn
	select {
	case socket = <-dialer.dialed:
	case err := <-finished: return fmt.Errorf("outbound ended before dial: %v", err)
	case <-ctx.Done(): return ctx.Err()
	}
	defer socket.Close()
	if err := report("ready", "client", "handler", s, socket.LocalAddr(), remote, 0, 1); err != nil { return err }
	for index := 1; index < 5; index++ {
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{packet(index, false)}); err != nil { return err }
		select {
		case err := <-collector.results: if err != nil { return err }
		case err := <-finished: return fmt.Errorf("outbound ended before reply %d: %v", index, err)
		case <-ctx.Done(): return ctx.Err()
		}
	}
	if err := report("handler_complete", "client", "handler", s, socket.LocalAddr(), remote, 4, 1); err != nil { return err }
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) { return fmt.Errorf("outbound cancel: %v", err) }
	case <-ctx.Done(): return ctx.Err()
	}
	if err := checkClosed(socket); err != nil { return err }
	if err := report("handler_closed", "client", "handler", s, socket.LocalAddr(), remote, 4, 1); err != nil { return err }

	// At this pin buf.Copy drops zero-length MultiBuffers in Process. Exercise
	// empties explicitly with production UDPWriter/UDPReader session APIs, and
	// identify this boundary in JSON instead of claiming Process supports it.
	method, err := ss.GetCipherMethod(s.method)
	if err != nil { return err }
	codec, err := ss.NewUDPPacketCodec(method, s.keys)
	if err != nil { return err }
	udpSession, err := codec.NewClientSession()
	if err != nil { return err }
	emptySocket, err := net.DialUDP("udp4", nil, remote)
	if err != nil { return err }
	defer emptySocket.Close()
	deadline, _ := ctx.Deadline()
	if err := emptySocket.SetDeadline(deadline); err != nil { return err }
	if err := report("empty_ready", "client", "session", s, emptySocket.LocalAddr(), remote, 0, 1); err != nil { return err }
	udpWriter := &ss.UDPWriter{Writer: emptySocket, Session: udpSession, Destination: destination(0, false)}
	udpReader := &ss.UDPReader{Reader: emptySocket, Session: udpSession}
	for _, index := range []int{0, 5} {
		if err := udpWriter.WriteMultiBuffer(buf.MultiBuffer{packet(index, false)}); err != nil { return err }
		mb, err := udpReader.ReadMultiBuffer()
		if err != nil { buf.ReleaseMulti(mb); return err }
		if len(mb) != 1 { buf.ReleaseMulti(mb); return fmt.Errorf("expected one empty reply") }
		err = checkPacket(index, true, mb[0])
		buf.ReleaseMulti(mb)
		if err != nil { return err }
	}
	if err := emptySocket.Close(); err != nil { return err }
	if err := checkClosed(emptySocket); err != nil { return err }
	if err := report("complete", "client", "handler+session", s, emptySocket.LocalAddr(), remote, packetCount, 2); err != nil { return err }
	if err := waitExit(); err != nil { return err }
	return report("closed", "client", "handler+session", s, emptySocket.LocalAddr(), remote, packetCount, 2)
}
