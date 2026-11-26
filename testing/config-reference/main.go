// Run only on the remote builder through generate.sh. No generated source is
// written to the reference tree. Descriptors include every linked Xray message.
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "sort"

    _ "github.com/xtls/xray-core/main/distro/all"
    "github.com/xtls/xray-core/core"
    "github.com/xtls/xray-core/infra/conf"
    "github.com/xtls/xray-core/infra/conf/serial"
    "google.golang.org/protobuf/encoding/protojson"
    "google.golang.org/protobuf/proto"
    "google.golang.org/protobuf/reflect/protodesc"
    "google.golang.org/protobuf/reflect/protoreflect"
    "google.golang.org/protobuf/reflect/protoregistry"
    "google.golang.org/protobuf/types/descriptorpb"
)

type fixture struct {
    Name string `json:"name"`
    Format string `json:"format"`
    Input string `json:"input"`
    DecodeError string `json:"decode_error,omitempty"`
    BuildError string `json:"build_error,omitempty"`
    Protobuf string `json:"protobuf,omitempty"`
    Config json.RawMessage `json:"config,omitempty"`
}

func must(err error) { if err != nil { panic(err) } }
func write(root, name string, value []byte) { must(os.WriteFile(filepath.Join(root, name), value, 0644)) }

func main() {
    if len(os.Args) != 2 { panic("expected output directory") }
    output := os.Args[1]
    must(os.MkdirAll(output, 0755))
    descriptors := &descriptorpb.FileDescriptorSet{}
    protoregistry.GlobalFiles.RangeFiles(func(file protoreflect.FileDescriptor) bool {
        descriptors.File = append(descriptors.File, protodesc.ToFileDescriptorProto(file))
        return true
    })
    sort.Slice(descriptors.File, func(i, j int) bool { return descriptors.File[i].GetName() < descriptors.File[j].GetName() })
    data, err := proto.MarshalOptions{Deterministic: true}.Marshal(descriptors)
    must(err)
    write(output, "descriptor.pb", data)

    fixtures := []fixture{
        {Name:"empty-json", Format:"json", Input:"{}"},
        {Name:"json-comments", Format:"json", Input:"# Python comment\n{ /* block */ \"stats\": {}, // Java comment\n \"outbounds\": [{\"tag\":\"direct\",\"protocol\":\"freedom\"}]}"},
        {Name:"yaml", Format:"yaml", Input:"stats: {}\noutbounds:\n  - tag: direct\n    protocol: freedom\n"},
        {Name:"toml", Format:"toml", Input:"[stats]\n[[outbounds]]\ntag = 'direct'\nprotocol = 'freedom'\n"},
        {Name:"policy-zero-negative", Format:"json", Input:`{"policy":{"levels":{"0":{"handshake":0,"connIdle":0,"uplinkOnly":0,"downlinkOnly":0,"bufferSize":-3},"1":{"handshake":7,"connIdle":11,"uplinkOnly":2,"downlinkOnly":3,"bufferSize":4,"statsUserUplink":true,"statsUserDownlink":true,"statsUserOnline":true},"2":null},"system":{"statsInboundUplink":true,"statsInboundDownlink":true,"statsOutboundUplink":true,"statsOutboundDownlink":true}},"stats":{}}`},
        {Name:"root-apps", Format:"json", Input:`{"api":{"tag":"api","services":["StatsService","HandlerService","LoggerService","RoutingService","ObservatoryService","ReflectionService","UnknownService"]},"metrics":{"listen":"127.0.0.1:11111"},"stats":{},"policy":{"levels":{"1":{"connIdle":2}}},"observatory":{"subjectSelector":["direct"],"probeURL":"http://127.0.0.1:12345/","probeInterval":"2.5s","enableConcurrency":true},"burstObservatory":{"subjectSelector":["direct"],"pingConfig":{"destination":"http://127.0.0.1:12345/","interval":"30s","sampling":3,"timeout":"2s"}},"outbounds":[{"tag":"direct","protocol":"freedom"}]}`},
        {Name:"socks", Format:"json", Input:`{"inbounds":[{"tag":"in","listen":"127.0.0.1","port":1080,"protocol":"socks","settings":{"auth":"password","accounts":[{"user":"alice","pass":"secret"}],"udp":true,"userLevel":1}}],"outbounds":[{"tag":"out","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081,"users":[{"user":"bob","pass":"password","level":1}]}]}}]}`},
        {Name:"invalid-json", Format:"json", Input:"{\"stats\":"},
        {Name:"invalid-yaml", Format:"yaml", Input:"stats: [\n"},
        {Name:"invalid-toml", Format:"toml", Input:"[stats\n"},
        {Name:"invalid-policy-type", Format:"json", Input:`{"policy":{"levels":{"1":{"connIdle":"bad"}}}}`},
        {Name:"invalid-policy-level", Format:"json", Input:`{"policy":{"levels":{"bad":{"connIdle":1}}}}`},
        {Name:"negative-policy-timeout", Format:"json", Input:`{"policy":{"levels":{"1":{"handshake":-1}}}}`},
        {Name:"empty-api-tag", Format:"json", Input:`{"api":{"services":["StatsService"]}}`},
        {Name:"empty-metrics", Format:"json", Input:`{"metrics":{}}`},
        {Name:"removed-reverse", Format:"json", Input:`{"reverse":{"bridges":[{"tag":"bridge","domain":"reverse.invalid"}]}}`},
        {Name:"removed-transport", Format:"json", Input:`{"transport":{}}`},
        {Name:"burst-missing-ping", Format:"json", Input:`{"burstObservatory":{}}`},
        {Name:"unknown-root-key", Format:"json", Input:`{"unrecognized":true}`},
    }
    for index := range fixtures {
        f := &fixtures[index]
        var config *conf.Config
        var decodeErr error
        switch f.Format {
        case "json": config, decodeErr = serial.DecodeJSONConfig(bytes.NewReader([]byte(f.Input)))
        case "yaml": config, decodeErr = serial.DecodeYAMLConfig(bytes.NewReader([]byte(f.Input)))
        case "toml": config, decodeErr = serial.DecodeTOMLConfig(bytes.NewReader([]byte(f.Input)))
        }
        write(output, f.Name+"."+f.Format, []byte(f.Input))
        if decodeErr != nil { f.DecodeError = decodeErr.Error(); continue }
        built, buildErr := config.Build()
        if buildErr != nil { f.BuildError = buildErr.Error(); continue }
        f.Protobuf = f.Name+".pb"
        binary, marshalErr := proto.MarshalOptions{Deterministic:true}.Marshal(built)
        must(marshalErr)
        write(output, f.Protobuf, binary)
        f.Config, err = protojson.MarshalOptions{UseProtoNames:true, EmitUnpopulated:true}.Marshal(built)
        must(err)
        // Verify the fixture is independently decodable as the native root.
        must(proto.Unmarshal(binary, new(core.Config)))
    }
    data, err = json.MarshalIndent(fixtures, "", "  ")
    must(err)
    write(output, "fixtures.json", append(data, '\n'))
    fmt.Printf("wrote %d schema files and %d config cases to %s\n", len(descriptors.File), len(fixtures), output)
}
