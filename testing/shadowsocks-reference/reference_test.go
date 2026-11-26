// This helper is copied into the exact pinned Xray-core package by generate.sh.
package shadowsocks

import (
    "bufio"
    "bytes"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "os"
    "testing"

    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/protocol"
)

const referencePassword = "classic-test-password"
const referenceCommit = "67756b3674d56b72c7a7e675e8dcd3f883e1b2f7"

type rustReferenceVector struct {
    GoCommit string `json:"go_commit"`
    Method string `json:"method"`
    Password string `json:"password"`
    Destination string `json:"destination"`
    Request string `json:"request"`
    Response string `json:"response"`
    UDP string `json:"udp"`
    UDPResponse string `json:"udp_response,omitempty"`
    RequestBody string `json:"request_body"`
    ResponseBody string `json:"response_body"`
    UDPBody string `json:"udp_body"`
}

func referenceUser(t *testing.T, method string) *protocol.MemoryUser {
    t.Helper()
    methods := map[string]CipherType{
        "aes-128-gcm": CipherType_AES_128_GCM,
        "aes-256-gcm": CipherType_AES_256_GCM,
        "chacha20-ietf-poly1305": CipherType_CHACHA20_POLY1305,
        "xchacha20-ietf-poly1305": CipherType_XCHACHA20_POLY1305,
    }
    cipher, ok := methods[method]
    if !ok { t.Fatalf("unknown method %q", method) }
    account, err := (&Account{Password: referencePassword, CipherType: cipher}).AsAccount()
    if err != nil { t.Fatal(err) }
    return &protocol.MemoryUser{Account: account, Email: "fixture@example", Level: 7}
}

func referenceWrite(t *testing.T, writer buf.Writer, body []byte) {
    t.Helper()
    buffer := buf.New()
    if _, err := buffer.Write(body); err != nil { t.Fatal(err) }
    if err := writer.WriteMultiBuffer(buf.MultiBuffer{buffer}); err != nil { t.Fatal(err) }
}

func referenceRead(t *testing.T, reader buf.Reader) []byte {
    t.Helper()
    var output []byte
    for {
        buffers, err := reader.ReadMultiBuffer()
        for _, buffer := range buffers { output = append(output, buffer.Bytes()...) }
        buf.ReleaseMulti(buffers)
        if err == io.EOF { return output }
        if err != nil { t.Fatal(err) }
    }
}

func TestRustClassicReferenceVectors(t *testing.T) {
    for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"} {
        user := referenceUser(t, method)
        request := &protocol.RequestHeader{Version: Version, Command: protocol.RequestCommandTCP, User: user, Address: net.DomainAddress("example.com"), Port: 443}
        var requestWire, responseWire bytes.Buffer
        writer, err := WriteTCPRequest(request, &requestWire)
        if err != nil { t.Fatal(err) }
        requestBody := []byte("Go request body across an authenticated record")
        referenceWrite(t, writer, requestBody)
        response, err := WriteTCPResponse(request, &responseWire)
        if err != nil { t.Fatal(err) }
        responseBody := []byte("Go response after client half-close")
        referenceWrite(t, response, responseBody)
        request.Command = protocol.RequestCommandUDP
        udpBody := []byte("Go UDP body")
        packet, err := EncodeUDPPacket(request, udpBody)
        if err != nil { t.Fatal(err) }
        record := rustReferenceVector{
            GoCommit: referenceCommit, Method: method, Password: referencePassword, Destination: "example.com:443",
            Request: hex.EncodeToString(requestWire.Bytes()), Response: hex.EncodeToString(responseWire.Bytes()), UDP: hex.EncodeToString(packet.Bytes()),
            RequestBody: hex.EncodeToString(requestBody), ResponseBody: hex.EncodeToString(responseBody), UDPBody: hex.EncodeToString(udpBody),
        }
        packet.Release()
        encoded, err := json.Marshal(record)
        if err != nil { t.Fatal(err) }
        fmt.Printf("SS_CLASSIC_VECTOR %s\n", encoded)
    }
}

func TestRustClassicReferenceDecode(t *testing.T) {
    path := os.Getenv("SS_CLASSIC_RUST_VECTORS")
    if path == "" { t.Fatal("SS_CLASSIC_RUST_VECTORS is required") }
    file, err := os.Open(path)
    if err != nil { t.Fatal(err) }
    defer file.Close()
    scanner := bufio.NewScanner(file)
    scanner.Buffer(make([]byte, 65536), 1024*1024)
    count := 0
    methods := make(map[string]bool)
    decode := func(encoded string) []byte {
        data, err := hex.DecodeString(encoded)
        if err != nil { t.Fatal(err) }
        return data
    }
    for scanner.Scan() {
        var record rustReferenceVector
        if err := json.Unmarshal(scanner.Bytes(), &record); err != nil { t.Fatal(err) }
        if record.GoCommit != referenceCommit || record.Password != referencePassword { t.Fatal("fixture provenance mismatch") }
        user := referenceUser(t, record.Method)
        validator := new(Validator)
        if err := validator.Add(user); err != nil { t.Fatal(err) }
        request, reader, err := ReadTCPSession(validator, bytes.NewReader(decode(record.Request)))
        if err != nil { t.Fatal(err) }
        if request.Address.String()+":"+request.Port.String() != record.Destination { t.Fatal("wrong TCP target") }
        if !bytes.Equal(referenceRead(t, reader), decode(record.RequestBody)) { t.Fatal("wrong TCP body") }
        response, err := ReadTCPResponse(user, bytes.NewReader(decode(record.Response)))
        if err != nil { t.Fatal(err) }
        if !bytes.Equal(referenceRead(t, response), decode(record.ResponseBody)) { t.Fatal("wrong response body") }
        packet := buf.New()
        if _, err := packet.Write(decode(record.UDP)); err != nil { t.Fatal(err) }
        decoded, payload, err := DecodeUDPPacket(validator, packet)
        if err != nil { t.Fatal(err) }
        if decoded.Address.String()+":"+decoded.Port.String() != record.Destination { t.Fatal("wrong UDP target") }
        if !bytes.Equal(payload.Bytes(), decode(record.UDPBody)) { t.Fatal("wrong UDP body") }
        packet.Release()
        if record.UDPResponse != "" {
            responsePacket := buf.New()
            if _, err := responsePacket.Write(decode(record.UDPResponse)); err != nil { t.Fatal(err) }
            responseHeader, responsePayload, err := DecodeUDPPacket(validator, responsePacket)
            if err != nil { t.Fatal(err) }
            if responseHeader.Address.String()+":"+responseHeader.Port.String() != record.Destination { t.Fatal("wrong native UDP response target") }
            if !bytes.Equal(responsePayload.Bytes(), decode(record.UDPBody)) { t.Fatal("wrong native UDP response body") }
            responsePacket.Release()
        }
        if methods[record.Method] { t.Fatalf("duplicate method %s", record.Method) }
        methods[record.Method] = true
        count++
    }
    if err := scanner.Err(); err != nil { t.Fatal(err) }
    if count != 4 { t.Fatalf("expected four methods, got %d", count) }
}
