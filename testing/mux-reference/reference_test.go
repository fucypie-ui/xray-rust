// Independent golden oracle: compiled only by generate.sh inside pinned Go.
package multiplex

import (
    "bytes"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "testing"

    "github.com/xtls/xray-core/common/bitmask"
    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/common/net"
)

func TestRustMuxReference(t *testing.T) {
    tcp4 := net.TCPDestination(net.ParseAddress("192.0.2.9"), 443)
    tcp6 := net.TCPDestination(net.ParseAddress("2001:db8::9"), 8443)
    domain := net.TCPDestination(net.DomainAddress("example.test"), 80)
    udp4 := net.UDPDestination(net.ParseAddress("198.51.100.53"), 53)
    udp6 := net.UDPDestination(net.ParseAddress("2001:db8::53"), 5353)
    udpDomain := net.UDPDestination(net.DomainAddress("dns.example.test"), 53)
    cases := []struct {
        name string
        id uint16
        status SessionStatus
        option bitmask.Byte
        target net.Destination
        payload []byte
        global [8]byte
    }{
        {"tcp-new-ipv4", 1, SessionStatusNew, OptionData, tcp4, []byte("hello"), [8]byte{}},
        {"tcp-new-ipv6", 65535, SessionStatusNew, 0, tcp6, nil, [8]byte{}},
        {"tcp-new-domain", 7, SessionStatusNew, OptionData, domain, []byte{0, 255, 1}, [8]byte{}},
        {"tcp-keep", 1, SessionStatusKeep, OptionData, net.Destination{}, []byte("response"), [8]byte{}},
        {"udp-new-ipv4", 2, SessionStatusNew, OptionData, udp4, []byte{1, 2}, [8]byte{}},
        {"udp-new-global", 3, SessionStatusNew, OptionData, udpDomain, []byte{3, 4}, [8]byte{1,2,3,4,5,6,7,8}},
        {"udp-keep-ipv6", 2, SessionStatusKeep, OptionData, udp6, []byte{5, 6, 7}, [8]byte{}},
        {"udp-keep-domain-empty", 3, SessionStatusKeep, OptionData, udpDomain, []byte{}, [8]byte{}},
        {"session-end", 1, SessionStatusEnd, 0, net.Destination{}, nil, [8]byte{}},
        {"session-reset", 2, SessionStatusEnd, OptionError, net.Destination{}, nil, [8]byte{}},
        {"keepalive", 0, SessionStatusKeepAlive, 0, net.Destination{}, nil, [8]byte{}},
        {"keepalive-data", 0, SessionStatusKeepAlive, OptionData, net.Destination{}, []byte("padding"), [8]byte{}},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            metadata := FrameMetadata{Target: tc.target, SessionID: tc.id, SessionStatus: tc.status, Option: tc.option, GlobalID: tc.global}
            wire := buf.New()
            defer wire.Release()
            if tc.target.Network == net.Network_UDP { wire.UDP = &tc.target }
            if err := metadata.WriteTo(wire); err != nil { t.Fatal(err) }
            encoded := append([]byte(nil), wire.Bytes()...)
            if tc.option.Has(OptionData) {
                encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(tc.payload)))
                encoded = append(encoded, tc.payload...)
            }
            reader := bytes.NewReader(encoded)
            var decoded FrameMetadata
            if err := decoded.Unmarshal(reader, false); err != nil { t.Fatal(err) }
            if decoded.SessionID != tc.id || decoded.SessionStatus != tc.status || decoded.Option != tc.option { t.Fatal("metadata mismatch") }
            if tc.option.Has(OptionData) {
                var size uint16
                if err := binary.Read(reader, binary.BigEndian, &size); err != nil { t.Fatal(err) }
                payload := make([]byte, int(size))
                if _, err := io.ReadFull(reader, payload); err != nil { t.Fatal(err) }
                if !bytes.Equal(payload, tc.payload) { t.Fatal("payload mismatch") }
            }
            if reader.Len() != 0 { t.Fatal("frame has unconsumed bytes") }
            host := ""
            network := ""
            if tc.target.Address != nil { host = tc.target.Address.String(); network = tc.target.Network.SystemString() }
            result, err := json.Marshal(map[string]any{
                "name": tc.name, "wire_hex": hex.EncodeToString(encoded), "session_id": tc.id,
                "status": byte(tc.status), "option": byte(tc.option), "host": host,
                "port": uint16(tc.target.Port), "network": network,
                "payload_hex": hex.EncodeToString(tc.payload), "global_id_hex": hex.EncodeToString(tc.global[:]),
            })
            if err != nil { t.Fatal(err) }
            fmt.Printf("MUX_REFERENCE_VECTOR %s
", result)
        })
    }
}
