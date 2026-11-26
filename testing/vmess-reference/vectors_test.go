// Fixture adapter for Xray-core 67756b3. It runs inside package encoding in a
// disposable source copy, so session fields are set without changing Go source.
package encoding

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    crand "crypto/rand"
    "crypto/sha256"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "hash/crc32"
    "os"
    "testing"

    "github.com/xtls/xray-core/common/bitmask"
    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/protocol"
    "github.com/xtls/xray-core/common/uuid"
    va "github.com/xtls/xray-core/proxy/vmess/aead"
)

type portRandom struct { n byte }
func (r *portRandom) Read(b []byte) (int,error) {
    for i := range b { b[i] = r.n; r.n++ }; return len(b),nil
}
func portHex(b []byte) string { return hex.EncodeToString(b) }
func portGCM(t *testing.T, key []byte) cipher.AEAD {
    block,e := aes.NewCipher(key); if e != nil { t.Fatal(e) }
    a,e := cipher.NewGCM(block); if e != nil { t.Fatal(e) }; return a
}
func portBody(t *testing.T, w buf.Writer, data []byte) {
    t.Helper()
    if e := w.WriteMultiBuffer(buf.MergeBytes(nil,data)); e != nil { t.Fatal(e) }
    if e := w.WriteMultiBuffer(nil); e != nil { t.Fatal(e) }
}
func TestPortReferenceVectors(t *testing.T) {
    old := crand.Reader; defer func(){crand.Reader=old}()
    id,e := uuid.ParseString("00112233-4455-6677-8899-aabbccddeeff"); if e != nil { t.Fatal(e) }
    key := protocol.NewID(id).CmdKey()
    var rk,ri [16]byte
    for i:=0;i<16;i++ {rk[i]=byte(i);ri[i]=byte(i+16)}
    sk,si := sha256.Sum256(rk[:]),sha256.Sum256(ri[:])
    var authPlain,authID [16]byte
    binary.BigEndian.PutUint64(authPlain[:8],1700000000)
    copy(authPlain[8:12],[]byte{0x20,0x21,0x22,0x23})
    binary.BigEndian.PutUint32(authPlain[12:],crc32.ChecksumIEEE(authPlain[:12]))
    va.NewCipherFromKey(key).Encrypt(authID[:],authPlain[:])
    plain := []byte{1}
    plain=append(plain,ri[:]...);plain=append(plain,rk[:]...)
    plain=append(plain,0x42,13,3,0,1,0x01,0xbb,2,11)
    plain=append(plain,[]byte("example.org")...)
    checksum:=make([]byte,4);binary.BigEndian.PutUint32(checksum,Authenticate(plain));plain=append(plain,checksum...)
    nonce:=[]byte{0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37}
    paths:=func(label string) []string{return []string{label,string(authID[:]),string(nonce)}}
    length:=make([]byte,2);binary.BigEndian.PutUint16(length,uint16(len(plain)))
    wire:=append([]byte(nil),authID[:]...)
    wire=append(wire,portGCM(t,va.KDF16(key,paths(va.KDFSaltConstVMessHeaderPayloadLengthAEADKey)...)).Seal(nil,va.KDF(key,paths(va.KDFSaltConstVMessHeaderPayloadLengthAEADIV)...)[:12],length,authID[:])...)
    wire=append(wire,nonce...)
    wire=append(wire,portGCM(t,va.KDF16(key,paths(va.KDFSaltConstVMessHeaderPayloadAEADKey)...)).Seal(nil,va.KDF(key,paths(va.KDFSaltConstVMessHeaderPayloadAEADIV)...)[:12],plain,authID[:])...)
    var fixedKey [16]byte;copy(fixedKey[:],key)
    opened,_,_,e:=va.OpenVMessAEADHeader(fixedKey,authID,bytes.NewReader(wire[16:]));if e!=nil||!bytes.Equal(opened,plain){t.Fatalf("Go header open: %v",e)}
    server:=&ServerSession{requestBodyKey:rk,requestBodyIV:ri,responseHeader:0x42}
    var response bytes.Buffer
    server.EncodeResponseHeader(&protocol.ResponseHeader{},&response)
    shake:=NewShakeSizeParser(ri[:]);masks:=make([]uint16,12)
    for i:=range masks { masks[i]=shake.next() }
    bodies:=[]map[string]interface{}{}
    for _,security:=range []protocol.SecurityType{protocol.SecurityType_AES128_GCM,protocol.SecurityType_CHACHA20_POLY1305} {
      for _,option:=range []byte{1,5,13,17,21,29} {
       for _,command:=range []protocol.RequestCommand{protocol.RequestCommandTCP,protocol.RequestCommandUDP} {
        payload:=make([]byte,257);for i:=range payload {payload[i]=byte(i)}
        request:=&protocol.RequestHeader{Version:1,Command:command,Security:security,Option:bitmask.Byte(option),Address:net.DomainAddress("example.org"),Port:443}
        client:=&ClientSession{requestBodyKey:rk,requestBodyIV:ri,responseHeader:0x42}
        var req,res bytes.Buffer
        crand.Reader=&portRandom{}
        writer,e:=client.EncodeRequestBody(request,&req);if e!=nil{t.Fatal(e)};portBody(t,writer,payload)
        crand.Reader=&portRandom{}
        writer,e=server.EncodeResponseBody(request,&res);if e!=nil{t.Fatal(e)};portBody(t,writer,payload)
        bodies=append(bodies,map[string]interface{}{"security":int(security),"options":option,"command":int(command),"payload":portHex(payload),"request_wire":portHex(req.Bytes()),"response_wire":portHex(res.Bytes())})
       }
      }
    }
    vectors:=map[string]interface{}{"commit":"67756b3674d56b72c7a7e675e8dcd3f883e1b2f7","user_id":id.String(),"timestamp":1700000000,"cmd_key":portHex(key),"auth_random":"20212223","auth_id":portHex(authID[:]),"connection_nonce":portHex(nonce),"header_plain":portHex(plain),"request_wire":portHex(wire),"request_key":portHex(rk[:]),"request_iv":portHex(ri[:]),"response_header_byte":0x42,"response_key":portHex(sk[:16]),"response_iv":portHex(si[:16]),"response_wire":portHex(response.Bytes()),"kdf_auth":portHex(va.KDF(key,va.KDFSaltConstAuthIDEncryptionKey)),"kdf_header":portHex(va.KDF(key,paths(va.KDFSaltConstVMessHeaderPayloadAEADKey)...)),"shake_masks":masks,"bodies":bodies}
    output:=os.Getenv("VMESS_VECTOR_OUTPUT");if output==""{t.Fatal("VMESS_VECTOR_OUTPUT is required")}
    data,e:=json.MarshalIndent(vectors,"","  ");if e!=nil{t.Fatal(e)}
    if e=os.WriteFile(output,append(data,'\n'),0644);e!=nil{t.Fatal(e)}
}
