// Test-only live UDP peer. Build inside the pinned module with build-peer.sh.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/kcp"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const reference = "67756b3674d56b72c7a7e675e8dcd3f883e1b2f7"
const requestSize, responseSize = 65539, 49159

func main() {
	mode := flag.String("mode", "server", "server or client")
	address := flag.String("address", "127.0.0.1:0", "UDP listen or remote address")
	mtu := flag.Uint("mtu", 1350, "raw mKCP MTU (200 or 1350)")
	flag.Parse()
	// Also bound operations without a connection deadline, including stdin.
	watchdog := time.AfterFunc(25*time.Second, func() {
		fmt.Fprintln(os.Stderr, "live Go mKCP peer exceeded 25s deadline")
		os.Exit(1)
	})
	defer watchdog.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := run(ctx, *mode, *address, *mtu); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func report(event, address string, mtu uint) error {
	return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
		"event": event, "source": reference, "address": address, "mtu": mtu,
	})
}

func run(ctx context.Context, mode, address string, mtu uint) error {
	if (mode != "server" && mode != "client") || (mtu != 200 && mtu != 1350) {
		return fmt.Errorf("expected server/client mode and MTU 200/1350")
	}
	// Use the production default factory, without TLS, finalmask, seed or header.
	value, err := internet.CreateTransportConfig(kcp.ProtocolName)
	if err != nil {
		return err
	}
	config := value.(*kcp.Config)
	config.Mtu = uint32(mtu)
	settings := &internet.MemoryStreamConfig{ProtocolName: kcp.ProtocolName, ProtocolSettings: config}
	dest, err := net.ParseDestination("udp:" + address)
	if err != nil {
		return err
	}
	var connection stat.Connection
	if mode == "server" {
		accepted := make(chan stat.Connection, 1)
		listener, err := kcp.NewListener(ctx, dest.Address, dest.Port, settings, func(c stat.Connection) {
			select {
			case accepted <- c:
			default:
				go c.Close()
			}
		})
		if err != nil {
			return err
		}
		defer listener.Close()
		if err := report("ready", listener.Addr().String(), mtu); err != nil {
			return err
		}
		select {
		case connection = <-accepted:
		case <-ctx.Done():
			return ctx.Err()
		}
	} else {
		connection, err = kcp.DialKCP(ctx, dest, settings)
		if err != nil {
			return err
		}
		if err := report("ready", connection.LocalAddr().String(), mtu); err != nil {
			return err
		}
	}
	c := connection.(*kcp.Connection)
	deadline, _ := ctx.Deadline()
	if err := c.SetDeadline(deadline); err != nil {
		return err
	}
	// ReadMultiBuffer is Xray's production stream path. At this pin, net.Conn.Read
	// lacks its PeerTerminating EOF branch; do not copy or patch either engine.
	reader := &buf.BufferedReader{Reader: c}
	defer func() { buf.ReleaseMulti(reader.Buffer) }()
	if mode == "client" {
		if err = writePayload(c, payload(requestSize, 0x31)); err == nil {
			err = readPayload(reader, payload(responseSize, 0xa7))
		}
	} else {
		if err = readPayload(reader, payload(requestSize, 0x31)); err == nil {
			err = writePayload(c, payload(responseSize, 0xa7))
		}
		if err == nil {
			var trailing [1]byte
			n, eof := reader.Read(trailing[:])
			if n != 0 || eof != io.EOF {
				err = fmt.Errorf("Rust shutdown: expected EOF after exact request, got n=%d err=%v", n, eof)
			}
		}
	}
	if err != nil {
		return err
	}
	// mKCP exposes Close, not TCP CloseWrite. Peer close also forbids writes.
	if err = c.Close(); err != nil {
		return err
	}
	if n, err := c.Write([]byte{0xff}); n != 0 || err != io.ErrClosedPipe {
		return fmt.Errorf("write after close: n=%d err=%v", n, err)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for c.State() != kcp.StateTerminated {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return fmt.Errorf("close state %v: %w", c.State(), ctx.Err())
		}
	}
	if err := report("complete", c.LocalAddr().String(), mtu); err != nil {
		return err
	}
	// Keep the Go listener's UDP socket alive until Rust's close timer finishes.
	// Stdio controls process lifetime only; all session bytes travel over mKCP.
	line, err := bufio.NewReader(io.LimitReader(os.Stdin, 16)).ReadString('\n')
	if err != nil || line != "exit\n" {
		return fmt.Errorf("expected exit control line, got %q: %v", line, err)
	}
	return nil
}

func payload(size, salt int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*73 + i/251 + salt)
	}
	return data
}

func writePayload(w io.Writer, data []byte) error {
	for i, offset := 0, 0; offset < len(data); i++ {
		end := min(offset+[]int{1, 17, 4093, 137, 8191}[i%5], len(data))
		n, err := w.Write(data[offset:end])
		if err != nil {
			return err
		}
		if n != end-offset {
			return io.ErrShortWrite
		}
		offset = end
	}
	return nil
}

func readPayload(r io.Reader, expected []byte) error {
	var buffer [997]byte
	for offset := 0; offset < len(expected); {
		size := min(len(buffer), len(expected)-offset)
		if _, err := io.ReadFull(r, buffer[:size]); err != nil {
			return fmt.Errorf("payload at %d: %w", offset, err)
		}
		if !bytes.Equal(buffer[:size], expected[offset:offset+size]) {
			return fmt.Errorf("binary payload mismatch at %d", offset)
		}
		offset += size
	}
	return nil
}
