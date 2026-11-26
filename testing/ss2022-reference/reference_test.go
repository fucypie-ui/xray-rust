// Copy this file into Xray-core/proxy/shadowsocks_2022 on the remote runner.
package shadowsocks_2022

import (
    "bytes"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "testing"

    "github.com/xtls/xray-core/common/net"
)

// TestRustReferenceVectors uses the authoritative KDF, cipher, address writer,
// and stream writer. Only time, salts and padding are fixed by this helper.
func TestRustReferenceVectors(t *testing.T) {
    for _, name := range []string{MethodAES128GCM, MethodAES256GCM} {
        m, err := GetCipherMethod(name)
        if err != nil { t.Fatal(err) }
        psk, salt, responseSalt := make([]byte, m.KeySaltLength), make([]byte, m.KeySaltLength), make([]byte, m.KeySaltLength)
        for i := range psk { psk[i] = byte(i); salt[i] = byte(0x20+i); responseSalt[i] = byte(0x60+i) }
        key := DeriveSessionSubKey(psk, salt, m.KeySaltLength)
        aead, err := m.NewAEAD(key)
        if err != nil { t.Fatal(err) }
        var variable bytes.Buffer
        if err := WriteAddressPort(&variable, net.TCPDestination(net.DomainAddress("example.com"), 443)); err != nil { t.Fatal(err) }
        variable.Write([]byte{0, 3, 0, 0, 0}) // padding length followed by padding
        variable.WriteString("early")
        fixed := make([]byte, RequestHeaderFixedChunkLength)
        fixed[0] = HeaderTypeClient
        binary.BigEndian.PutUint64(fixed[1:9], 1700000000)
        binary.BigEndian.PutUint16(fixed[9:11], uint16(variable.Len()))
        var request bytes.Buffer
        request.Write(salt)
        sw := NewStreamWriter(&request, aead)
        request.Write(aead.Seal(nil, sw.Nonce(), fixed, nil)); IncreaseNonce(sw.Nonce())
        request.Write(aead.Seal(nil, sw.Nonce(), variable.Bytes(), nil)); IncreaseNonce(sw.Nonce())
        if _, err := sw.Write([]byte("request body")); err != nil { t.Fatal(err) }

        responseKey := DeriveSessionSubKey(psk, responseSalt, m.KeySaltLength)
        responseAEAD, err := m.NewAEAD(responseKey)
        if err != nil { t.Fatal(err) }
        var response bytes.Buffer
        response.Write(responseSalt)
        rw := NewStreamWriter(&response, responseAEAD)
        responseFixed := make([]byte, 11+m.KeySaltLength)
        responseFixed[0] = HeaderTypeServer
        binary.BigEndian.PutUint64(responseFixed[1:9], 1700000000)
        copy(responseFixed[9:], salt)
        binary.BigEndian.PutUint16(responseFixed[9+m.KeySaltLength:], uint16(len("first response")))
        response.Write(responseAEAD.Seal(nil, rw.Nonce(), responseFixed, nil)); IncreaseNonce(rw.Nonce())
        response.Write(responseAEAD.Seal(nil, rw.Nonce(), []byte("first response"), nil)); IncreaseNonce(rw.Nonce())
        if _, err := rw.Write([]byte("response body")); err != nil { t.Fatal(err) }
        record := map[string]any{
            "method": name, "timestamp": uint64(1700000000), "destination": "example.com:443",
            "psk": hex.EncodeToString(psk), "salt": hex.EncodeToString(salt), "response_salt": hex.EncodeToString(responseSalt),
            "subkey": hex.EncodeToString(key), "request": hex.EncodeToString(request.Bytes()), "response": hex.EncodeToString(response.Bytes()),
            "padding": "000000", "early_data": hex.EncodeToString([]byte("early")),
            "request_body": hex.EncodeToString([]byte("request body")), "response_initial": hex.EncodeToString([]byte("first response")),
            "response_body": hex.EncodeToString([]byte("response body")),
        }
        encoded, err := json.Marshal(record)
        if err != nil { t.Fatal(err) }
        fmt.Printf("SS2022_VECTOR %s\n", encoded)
    }
}
