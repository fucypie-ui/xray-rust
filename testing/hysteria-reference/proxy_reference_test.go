package hysteria

import (
    "bytes"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "testing"

    ht "github.com/xtls/xray-core/transport/internet/hysteria"
)

// Run only in a disposable Ubuntu CI checkout of the pinned Go reference.
func TestRustReferenceVectors(t *testing.T) {
    oldRequest, oldResponse := ht.TcpRequestPadding, ht.TcpResponsePadding
    defer func() { ht.TcpRequestPadding, ht.TcpResponsePadding = oldRequest, oldResponse }()
    ht.TcpRequestPadding.Min, ht.TcpRequestPadding.Max = 0, 1
    ht.TcpResponsePadding.Min, ht.TcpResponsePadding.Max = 0, 1
    type frame struct { Address string `json:"address"`; Hex string `json:"hex"` }
    requests := []frame{}
    for _, address := range []string{"example.com:443", "[2001:db8::1]:53", "127.0.0.1:80"} {
        var b bytes.Buffer
        if err := WriteTCPRequest(&b, address); err != nil { t.Fatal(err) }
        decoded, err := ReadTCPRequest(bytes.NewReader(b.Bytes()))
        if err != nil || decoded != address { t.Fatalf("request: %q %v", decoded, err) }
        requests = append(requests, frame{address, hex.EncodeToString(b.Bytes())})
    }
    type response struct { OK bool `json:"ok"`; Message string `json:"message"`; Hex string `json:"hex"` }
    responses := []response{}
    for _, item := range []struct{ok bool; msg string}{{true, ""}, {false, "connection refused"}} {
        var b bytes.Buffer
        if err := WriteTCPResponse(&b, item.ok, item.msg); err != nil { t.Fatal(err) }
        responses = append(responses, response{item.ok, item.msg, hex.EncodeToString(b.Bytes())})
    }
    message := UDPMessage{SessionID: 0x01020304, PacketID: 0x0506, FragID: 0, FragCount: 1, Addr: "dns.example:53", Data: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}
    serialize := func(m *UDPMessage) string {
        b := make([]byte, m.Size())
        if m.Serialize(b) < 0 { t.Fatal("serialize failed") }
        // Go InterConn.Write injects the session ID after proxy serialization.
        binary.BigEndian.PutUint32(b, m.SessionID)
        if _, err := ParseUDPMessage(b); err != nil { t.Fatal(err) }
        return hex.EncodeToString(b)
    }
    wire := serialize(&message)
    fragments := []string{}
    for _, fragment := range FragUDPMessage(&message, message.HeaderSize()+3) {
        fragments = append(fragments, serialize(&fragment))
    }
    bad := []string{"", "0000000000000001", "000000000000000100", "00000000000000010161", "000000000000000140"}
    for _, s := range bad {
        b, _ := hex.DecodeString(s)
        if _, err := ParseUDPMessage(b); err == nil { t.Fatalf("Go accepted invalid %q", s) }
    }
    record := map[string]interface{}{"kind": "protocol", "reference": "67756b3674d56b72c7a7e675e8dcd3f883e1b2f7", "requests": requests, "responses": responses, "udp": wire, "fragments": fragments, "invalid_udp": bad}
    b, err := json.Marshal(record); if err != nil { t.Fatal(err) }
    fmt.Printf("HYSTERIA_VECTOR %s\n", b)
}
