// Independent extended vectors; the original AES helper and outputs remain frozen.
package shadowsocks_2022

import (
    "bytes"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "testing"

    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/common/net"
)

const rustExtendedTimestamp uint64 = 1700000000
const rustClientSessionID uint64 = 0x0102030405060708
const rustServerSessionID uint64 = 0x1112131415161718

func rustNormalizeUDP(t *testing.T, method *CipherMethod, keys [][]byte, wire []byte, identities int, nonceByte byte) []byte {
    t.Helper()
    finalKey := keys[len(keys)-1]
    if method.IsChaCha {
        aead, err := method.NewUDPCipher(finalKey)
        if err != nil { t.Fatal(err) }
        plain, err := aead.Open(nil, wire[:PacketNonceSize], wire[PacketNonceSize:], nil)
        if err != nil { t.Fatal(err) }
        binary.BigEndian.PutUint64(plain[17:25], rustExtendedTimestamp)
        nonce := make([]byte, PacketNonceSize)
        for i := range nonce { nonce[i] = nonceByte + byte(i) }
        return append(nonce, aead.Seal(nil, nonce, plain, nil)...)
    }
    headerKey := finalKey
    if identities > 0 { headerKey = keys[0] }
    block, err := method.NewBlock(headerKey)
    if err != nil { t.Fatal(err) }
    raw := make([]byte, AESBlockSize)
    block.Decrypt(raw, wire[:AESBlockSize])
    bodyKey := DeriveSessionSubKey(finalKey, raw[:8], method.KeySaltLength)
    aead, err := method.NewAEAD(bodyKey)
    if err != nil { t.Fatal(err) }
    offset := AESBlockSize * (1+identities)
    plain, err := aead.Open(nil, raw[4:], wire[offset:], nil)
    if err != nil { t.Fatal(err) }
    binary.BigEndian.PutUint64(plain[1:9], rustExtendedTimestamp)
    out := append([]byte(nil), wire[:offset]...)
    return append(out, aead.Seal(nil, raw[4:], plain, nil)...)
}

func rustNormalizeTCPResponse(t *testing.T, method *CipherMethod, key, salt, wire []byte) []byte {
    t.Helper()
    oldCipher, err := method.NewAEAD(DeriveSessionSubKey(key, wire[:method.KeySaltLength], method.KeySaltLength))
    if err != nil { t.Fatal(err) }
    newCipher, err := method.NewAEAD(DeriveSessionSubKey(key, salt, method.KeySaltLength))
    if err != nil { t.Fatal(err) }
    out := append([]byte(nil), salt...)
    offset := method.KeySaltLength
    var nonce [StreamNonceSize]byte
    take := func(length int) []byte {
        chunk, err := oldCipher.Open(nil, nonce[:], wire[offset:offset+length+AEADTagSize], nil)
        if err != nil { t.Fatal(err) }
        offset += length + AEADTagSize
        return chunk
    }
    seal := func(plain []byte) { out = append(out, newCipher.Seal(nil, nonce[:], plain, nil)...); IncreaseNonce(nonce[:]) }
    fixed := take(11+method.KeySaltLength)
    binary.BigEndian.PutUint64(fixed[1:9], rustExtendedTimestamp)
    initialLen := int(binary.BigEndian.Uint16(fixed[9+method.KeySaltLength:]))
    seal(fixed)
    if initialLen > 0 { seal(take(initialLen)) }
    for offset < len(wire) {
        length := take(2)
        seal(length)
        seal(take(int(binary.BigEndian.Uint16(length))))
    }
    return out
}

func TestRustExtendedReferenceVectors(t *testing.T) {
    for _, name := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
        method, err := GetCipherMethod(name)
        if err != nil { t.Fatal(err) }
        keyLen := method.KeySaltLength
        key, salt, responseSalt := make([]byte,keyLen), make([]byte,keyLen), make([]byte,keyLen)
        master, relay := make([]byte,keyLen), make([]byte,keyLen)
        for i := range key { key[i]=byte(i); salt[i]=byte(0x20+i); responseSalt[i]=byte(0x60+i); master[i]=byte(0x80+i); relay[i]=byte(0xa0+i) }
        keys := [][]byte{key}
        if !method.IsChaCha { keys = [][]byte{master,relay,key} }
        dest := net.TCPDestination(net.DomainAddress("example.com"),443)
        early := bytes.Repeat([]byte("e"),MaxPaddingLength) // no random padding in production encoder
        var request bytes.Buffer
        writer, err := WriteTCPRequest(&request,method,keys,dest,salt,early)
        if err != nil { t.Fatal(err) }
        if err := writer.WriteMultiBuffer(buf.MergeBytes(nil,[]byte("extended request body"))); err != nil { t.Fatal(err) }
        req := append([]byte(nil),request.Bytes()...)
        aead, err := method.NewAEAD(DeriveSessionSubKey(key,salt,keyLen))
        if err != nil { t.Fatal(err) }
        offset := keyLen+(len(keys)-1)*AESBlockSize
        nonce := make([]byte,StreamNonceSize)
        fixed, err := aead.Open(nil,nonce,req[offset:offset+RequestHeaderFixedChunkLength+AEADTagSize],nil)
        if err != nil { t.Fatal(err) }
        binary.BigEndian.PutUint64(fixed[1:9],rustExtendedTimestamp)
        copy(req[offset:],aead.Seal(nil,nonce,fixed,nil))
        var response bytes.Buffer
        rw := NewServerStreamWriter(&response,method,key,salt)
        if _, err := rw.Write([]byte("extended first response")); err != nil { t.Fatal(err) }
        if _, err := rw.Write([]byte("extended response body")); err != nil { t.Fatal(err) }
        resp := rustNormalizeTCPResponse(t,method,key,responseSalt,response.Bytes())
        codec, err := NewUDPPacketCodec(method,keys)
        if err != nil { t.Fatal(err) }
        session, err := codec.NewClientSession()
        if err != nil { t.Fatal(err) }
        session.clientSessionID=rustClientSessionID
        sid := make([]byte,8); binary.BigEndian.PutUint64(sid,rustClientSessionID)
        if !method.IsChaCha {
            session.clientBodyCipher,err=method.NewAEAD(DeriveSessionSubKey(key,sid,keyLen))
            if err != nil { t.Fatal(err) }
        }
        udp, err := session.EncodePacket(dest,[]byte("extended UDP request"))
        if err != nil { t.Fatal(err) }
        udpRequest := rustNormalizeUDP(t,method,keys,udp.Bytes(),len(keys)-1,0xc0)
        udp.Release()
        server := new(ServerUDPSession)
        if err := server.EnsureServerState(method,key); err != nil { t.Fatal(err) }
        server.ServerSessionID=rustServerSessionID
        if !method.IsChaCha {
            binary.BigEndian.PutUint64(sid,rustServerSessionID)
            server.serverBodyCipher,err=method.NewAEAD(DeriveSessionSubKey(key,sid,keyLen))
            if err != nil { t.Fatal(err) }
        }
        udpResp,err:=server.EncodeServerPacket(method,rustClientSessionID,dest,[]byte("extended UDP response"))
        if err != nil { t.Fatal(err) }
        udpResponse:=rustNormalizeUDP(t,method,[][]byte{key},udpResp,0,0xe0)
        keyHex:=make([]string,len(keys)); for i,k:=range keys { keyHex[i]=hex.EncodeToString(k) }
        record:=map[string]any{
            "method":name,"timestamp":rustExtendedTimestamp,"keys":keyHex,
            "salt":hex.EncodeToString(salt),"response_salt":hex.EncodeToString(responseSalt),
            "destination":"example.com:443","padding":"","early_data":hex.EncodeToString(early),
            "request":hex.EncodeToString(req),"response":hex.EncodeToString(resp),
            "request_body":hex.EncodeToString([]byte("extended request body")),
            "response_initial":hex.EncodeToString([]byte("extended first response")),"response_body":hex.EncodeToString([]byte("extended response body")),
            "udp_request":hex.EncodeToString(udpRequest),"udp_response":hex.EncodeToString(udpResponse),
            "client_session_id":rustClientSessionID,"server_session_id":rustServerSessionID,
            "udp_request_payload":hex.EncodeToString([]byte("extended UDP request")),"udp_response_payload":hex.EncodeToString([]byte("extended UDP response")),
        }
        encoded,err:=json.Marshal(record); if err != nil { t.Fatal(err) }
        fmt.Printf("SS2022_EXTENDED_VECTOR %s\n",encoded)
    }
}
