// Independent grpc-go reflection clients and a real pinned Xray Commander baseline.
// Build only inside the exact reference archive; no generated fixtures or server clone.
package main

import (
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "net"
    "os"
    "runtime"
    "runtime/debug"
    "slices"
    "strconv"
    "strings"
    "time"

    _ "github.com/xtls/xray-core/app/proxyman/inbound"
    _ "github.com/xtls/xray-core/app/proxyman/outbound"
    "github.com/xtls/xray-core/common/log"
    "github.com/xtls/xray-core/core"
    featurestats "github.com/xtls/xray-core/features/stats"
    "github.com/xtls/xray-core/infra/conf"
    "golang.org/x/net/proxy"
    "google.golang.org/grpc"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/credentials/insecure"
    "google.golang.org/grpc/metadata"
    v1 "google.golang.org/grpc/reflection/grpc_reflection_v1"
    alpha "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
    "google.golang.org/grpc/status"
    "google.golang.org/protobuf/proto"
    "google.golang.org/protobuf/reflect/protodesc"
    "google.golang.org/protobuf/reflect/protoreflect"
    "google.golang.org/protobuf/reflect/protoregistry"
    "google.golang.org/protobuf/types/descriptorpb"
    "google.golang.org/protobuf/types/dynamicpb"
    "google.golang.org/protobuf/types/gofeaturespb"
)

const reference = "67756b3674d56b72c7a7e675e8dcd3f883e1b2f7"
const counterName = "reflection.reference.sentinel"
const counterValue int64 = 424242
const routedTarget = "api-reflection.reference.invalid:18080"
const echoHost = "reflection.echo.invalid:8443/μ"
const handlerSymbol = "xray.app.proxyman.command.HandlerService"
const statsSymbol = "xray.app.stats.command.StatsService"

type command struct {
    Mode string `json:"mode"`
    Address string `json:"address"`
    Socks string `json:"socks"`
    Version string `json:"version"`
    Profile string `json:"profile"`
    TimeoutMS int `json:"timeout_ms"`
}

type result struct {
    Services []string `json:"services"`
    HandlerFiles []string `json:"handler_files"`
    HandlerSHA256 string `json:"handler_sha256"`
    Checks []string `json:"checks"`
    Queries int `json:"queries"`
    Echoes int `json:"echoes"`
    NotFound int `json:"not_found"`
    FreshClosures int `json:"fresh_closures"`
    RepeatedRoots int `json:"repeated_roots"`
    CleanEOF int `json:"clean_eof"`
    EmptyEOF int `json:"empty_eof"`
    TerminalCode int `json:"terminal_code"`
    CancelledCode int `json:"cancelled_code"`
    DynamicQueries int `json:"dynamic_queries"`
    DynamicValue int64 `json:"dynamic_value"`
    LookupErrors []lookupObservation `json:"lookup_errors"`
    Streams []streamObservation `json:"streams"`
}
type lookupObservation struct {
    Query string `json:"query"`
    Code int32 `json:"code"`
    Message string `json:"message"`
}
type metadataEntry struct {
    Key string `json:"key"`
    ValuesBase64 []string `json:"values_base64"`
}
type streamObservation struct {
    Scenario string `json:"scenario"`
    EOF bool `json:"eof"`
    Code int `json:"code"`
    Message string `json:"message"`
    Headers []metadataEntry `json:"headers"`
    Trailers []metadataEntry `json:"trailers"`
}
type event struct {
    Event string `json:"event"`
    Reference string `json:"reference"`
    GRPCVersion string `json:"grpc_version"`
    ProtobufVersion string `json:"protobuf_version"`
    GoVersion string `json:"go_version"`
    Mode string `json:"mode"`
    Address string `json:"address"`
    Socks string `json:"socks"`
    Version string `json:"version"`
    Profile string `json:"profile"`
    Result result `json:"result"`
}

func check(ok bool, format string, args ...any) {
    if !ok { panic(fmt.Errorf(format, args...)) }
}
func must[T any](value T, err error) T {
    if err != nil { panic(err) }
    return value
}
func must0(err error) { if err != nil { panic(err) } }

func loopback(address string, zero bool) error {
    host, port, err := net.SplitHostPort(address)
    if err != nil { return err }
    ip := net.ParseIP(host)
    n, err := strconv.Atoi(port)
    if ip == nil || ip.To4() == nil || !ip.IsLoopback() || err != nil || n < 0 || n > 65535 || !zero && n == 0 {
        return fmt.Errorf("IPv4 loopback and a valid port required")
    }
    return nil
}

func readCommand() (command, error) {
    var c command
    raw, err := io.ReadAll(io.LimitReader(os.Stdin, 65537))
    if err != nil { return c, err }
    if len(raw) > 65536 { return c, fmt.Errorf("JSON control exceeds 64 KiB") }
    decoder := json.NewDecoder(bytes.NewReader(raw))
    first, err := decoder.Token()
    if err != nil || first != json.Delim('{') { return c, fmt.Errorf("expected JSON control object") }
    fields := []string{"mode", "address", "socks", "version", "profile", "timeout_ms"}
    seen := make(map[string]bool)
    for decoder.More() {
        token, err := decoder.Token()
        if err != nil { return c, err }
        name, ok := token.(string)
        if !ok || seen[name] || !slices.Contains(fields, name) { return c, fmt.Errorf("unknown/duplicate/invalid JSON control key") }
        seen[name] = true
        var value json.RawMessage
        if err := decoder.Decode(&value); err != nil { return c, err }
        if bytes.Equal(bytes.TrimSpace(value), []byte("null")) { return c, fmt.Errorf("null control field %s", name) }
    }
    if _, err := decoder.Token(); err != nil {
        if err == io.EOF { return c, fmt.Errorf("unexpected end of JSON input") }
        return c, err
    }
    decoder = json.NewDecoder(bytes.NewReader(raw))
    decoder.DisallowUnknownFields()
    if err := decoder.Decode(&c); err != nil { return c, err }
    var extra any
    if err := decoder.Decode(&extra); err != io.EOF { return c, fmt.Errorf("trailing JSON control") }
    for _, name := range fields { if !seen[name] { return c, fmt.Errorf("missing JSON control field %s", name) } }
    if c.Mode != "client" && c.Mode != "baseline" { return c, fmt.Errorf("unsupported mode %q", c.Mode) }
    if c.Version != "v1" && c.Version != "v1alpha" { return c, fmt.Errorf("unsupported reflection version %q", c.Version) }
    if !slices.Contains([]string{"full", "stats", "reflection", "disabled"}, c.Profile) { return c, fmt.Errorf("unsupported profile %q", c.Profile) }
    if c.TimeoutMS < 1 || c.TimeoutMS > 15000 { return c, fmt.Errorf("timeout_ms must be in 1..15000") }
    if c.Socks != "" {
        if c.Mode != "client" || c.Address != routedTarget { return c, fmt.Errorf("SOCKS requires client mode and the fixed routed target") }
        if err := loopback(c.Socks, false); err != nil { return c, err }
    } else if err := loopback(c.Address, c.Mode == "baseline"); err != nil { return c, err }
    return c, nil
}

func services(profile string) []string {
    switch profile {
    case "full": return []string{"ReflectionService", "HandlerService", "LoggerService", "StatsService", "RoutingService", "ObservatoryService"}
    case "stats": return []string{"ReflectionService", "StatsService"}
    case "reflection": return []string{"ReflectionService"}
    default: return []string{"StatsService"}
    }
}
func visible(profile string) []string {
    names := []string{"grpc.reflection.v1.ServerReflection", "grpc.reflection.v1alpha.ServerReflection"}
    if profile == "full" {
        for _, name := range []string{"log.command.LoggerService", "proxyman.command.HandlerService", "router.command.RoutingService", "stats.command.StatsService"} {
            names = append(names, "xray.app."+name, "v2ray.core.app."+name)
        }
        names = append(names, "xray.core.app.observatory.command.ObservatoryService")
    } else if profile == "stats" {
        names = append(names, statsSymbol, "v2ray.core.app.stats.command.StatsService")
    }
    slices.Sort(names)
    return names
}

// Both branches call production generated clients. Alpha conversion is ordinary
// protobuf wire conversion, not a hand-written gRPC codec or reflection server.
type reflectionStream interface {
    Send(*v1.ServerReflectionRequest) error
    Recv() (*v1.ServerReflectionResponse, error)
    CloseSend() error
    Header() (metadata.MD, error)
    Trailer() metadata.MD
}
type alphaStream struct { alpha.ServerReflection_ServerReflectionInfoClient }
func (s alphaStream) Send(request *v1.ServerReflectionRequest) error {
    converted := new(alpha.ServerReflectionRequest)
    must0(proto.Unmarshal(must(proto.Marshal(request)), converted))
    return s.ServerReflection_ServerReflectionInfoClient.Send(converted)
}
func (s alphaStream) Recv() (*v1.ServerReflectionResponse, error) {
    response, err := s.ServerReflection_ServerReflectionInfoClient.Recv()
    if err != nil { return nil, err }
    converted := new(v1.ServerReflectionResponse)
    must0(proto.Unmarshal(must(proto.Marshal(response)), converted))
    return converted, nil
}
type runner struct {
    ctx context.Context
    conn *grpc.ClientConn
    version string
    result result
}
func (r *runner) open(ctx context.Context) reflectionStream {
    if r.version == "v1" { return must(v1.NewServerReflectionClient(r.conn).ServerReflectionInfo(ctx)) }
    return alphaStream{must(alpha.NewServerReflectionClient(r.conn).ServerReflectionInfo(ctx))}
}
func (r *runner) ask(stream reflectionStream, request *v1.ServerReflectionRequest) *v1.ServerReflectionResponse {
    request.Host = echoHost
    must0(stream.Send(request))
    response := must(stream.Recv())
    check(response != nil && response.GetValidHost() == echoHost && proto.Equal(response.GetOriginalRequest(), request), "host/original_request echo differs")
    r.result.Queries++
    r.result.Echoes++
    return response
}
func snapshotMetadata(md metadata.MD) []metadataEntry {
    keys := make([]string, 0, len(md))
    for key := range md { keys = append(keys, key) }
    slices.Sort(keys)
    entries := make([]metadataEntry, 0, len(keys))
    for _, key := range keys {
        values := make([]string, 0, len(md[key]))
        // Sort keys only. Preserve every value, duplicate and per-key value
        // order. Base64 is lossless even for arbitrary binary metadata.
        for _, value := range md[key] { values = append(values, base64.StdEncoding.EncodeToString([]byte(value))) }
        entries = append(entries, metadataEntry{Key:key, ValuesBase64:values})
    }
    return entries
}
func (r *runner) observe(stream reflectionStream, scenario string, err error) streamObservation {
    check(err != nil, "terminal observation requires an actual receive error")
    // Recv's io.EOF represents an observed OK termination, not a status error.
    // Preserve the distinction instead of converting EOF into UNKNOWN (2).
    terminal := err
    if err == io.EOF { terminal = nil }
    observed := status.Convert(terminal)
    // BOTH reads follow terminal Recv. In particular, do not call Header before
    // Send/Recv or CloseSend: a trailers-only empty stream would deadlock.
    headers := must(stream.Header())
    outcome := streamObservation{Scenario:scenario, EOF:err == io.EOF,
        Code:int(observed.Code()), Message:observed.Message(),
        Headers:snapshotMetadata(headers), Trailers:snapshotMetadata(stream.Trailer())}
    r.result.Streams = append(r.result.Streams, outcome)
    return outcome
}
func (r *runner) finish(stream reflectionStream, scenario string) {
    must0(stream.CloseSend())
    response, err := stream.Recv()
    check(response == nil && err == io.EOF, "expected clean terminal EOF, got response=%v err=%v", response, err)
    r.observe(stream, scenario, err)
    r.result.CleanEOF++
}
func (r *runner) list(stream reflectionStream, expected []string) {
    response := r.ask(stream, &v1.ServerReflectionRequest{MessageRequest:&v1.ServerReflectionRequest_ListServices{ListServices:"ignored nonempty filter"}})
    list := response.GetListServicesResponse()
    check(list != nil, "list_services returned %T", response.GetMessageResponse())
    names := make([]string, 0, len(list.GetService()))
    for _, service := range list.GetService() { names = append(names, service.GetName()) }
    check(slices.Equal(names, expected), "sorted service visibility: got %v, want %v", names, expected)
}
func symbol(name string) *v1.ServerReflectionRequest {
    return &v1.ServerReflectionRequest{MessageRequest:&v1.ServerReflectionRequest_FileContainingSymbol{FileContainingSymbol:name}}
}
func filename(name string) *v1.ServerReflectionRequest {
    return &v1.ServerReflectionRequest{MessageRequest:&v1.ServerReflectionRequest_FileByFilename{FileByFilename:name}}
}
func extension(number int32) *v1.ServerReflectionRequest {
    return &v1.ServerReflectionRequest{MessageRequest:&v1.ServerReflectionRequest_FileContainingExtension{FileContainingExtension:&v1.ExtensionRequest{ContainingType:"google.protobuf.FeatureSet", ExtensionNumber:number}}}
}
func numbers(name string) *v1.ServerReflectionRequest {
    return &v1.ServerReflectionRequest{MessageRequest:&v1.ServerReflectionRequest_AllExtensionNumbersOfType{AllExtensionNumbersOfType:name}}
}
func closure(root protoreflect.FileDescriptor) []protoreflect.FileDescriptor {
    queue := []protoreflect.FileDescriptor{root}
    seen := make(map[string]bool)
    files := []protoreflect.FileDescriptor{}
    for len(queue) != 0 {
        file := queue[0]
        queue = queue[1:]
        if seen[file.Path()] { continue }
        seen[file.Path()] = true
        check(!file.IsPlaceholder(), "placeholder file %s", file.Path())
        files = append(files, file)
        for i := 0; i < file.Imports().Len(); i++ { queue = append(queue, file.Imports().Get(i)) }
    }
    return files
}
type descriptorCache map[string]*descriptorpb.FileDescriptorProto
func (r *runner) files(stream reflectionStream, request *v1.ServerReflectionRequest, root protoreflect.FileDescriptor, cache descriptorCache) *protoregistry.Files {
    repeated := cache[root.Path()] != nil
    expected := []string{}
    for i, file := range closure(root) { if i == 0 || cache[file.Path()] == nil { expected = append(expected, file.Path()) } }
    response := r.ask(stream, request)
    descriptors := response.GetFileDescriptorResponse()
    check(descriptors != nil, "descriptor query returned %T", response.GetMessageResponse())
    actual := []string{}
    received := make(map[string]bool)
    for _, encoded := range descriptors.GetFileDescriptorProto() {
        file := new(descriptorpb.FileDescriptorProto)
        must0(proto.Unmarshal(encoded, file))
        path := file.GetName()
        check(path != "" && !received[path], "empty or duplicate response file %q", path)
        received[path] = true
        actual = append(actual, path)
        if previous := cache[path]; previous != nil { check(proto.Equal(previous, file), "repeated descriptor changed: %s", path) }
        cache[path] = file
    }
    check(len(actual) > 0 && actual[0] == root.Path(), "requested root must always be first, got %v", actual)
    slices.Sort(actual)
    slices.Sort(expected)
    check(slices.Equal(actual, expected), "descriptor cache response: got %v want %v", actual, expected)
    set := &descriptorpb.FileDescriptorSet{}
    for _, file := range cache { set.File = append(set.File, file) }
    // NewFiles owns a new empty registry and resolves only the returned graph.
    // Never use GlobalFiles as a fallback for a missing reflected dependency.
    registry := must(protodesc.NewFiles(set))
    for _, path := range actual {
        parsed := must(registry.FindFileByPath(path))
        authority := must(protoregistry.GlobalFiles.FindFileByPath(path))
        check(proto.Equal(protodesc.ToFileDescriptorProto(parsed), protodesc.ToFileDescriptorProto(authority)), "reflected schema differs from pinned descriptor: %s", path)
    }
    if repeated { r.result.RepeatedRoots++ }
    if root.Path() == must(protoregistry.GlobalFiles.FindDescriptorByName(handlerSymbol)).ParentFile().Path() && !repeated {
        check(len(actual) == 4, "Handler closure must contain exactly four files, got %v", actual)
        r.result.FreshClosures++
        if r.result.HandlerSHA256 == "" {
            r.result.HandlerFiles = actual
            canonical := &descriptorpb.FileDescriptorSet{}
            for _, path := range actual { canonical.File = append(canonical.File, protodesc.ToFileDescriptorProto(must(registry.FindFileByPath(path)))) }
            digest := sha256.Sum256(must((proto.MarshalOptions{Deterministic:true}).Marshal(canonical)))
            r.result.HandlerSHA256 = hex.EncodeToString(digest[:])
        }
    }
    return registry
}
func (r *runner) dynamicStats(registry *protoregistry.Files) {
    service := must(registry.FindDescriptorByName(statsSymbol)).(protoreflect.ServiceDescriptor)
    method := service.Methods().ByName("QueryStats")
    check(method != nil && !method.IsStreamingClient() && !method.IsStreamingServer(), "missing unary QueryStats descriptor")
    input, output := dynamicpb.NewMessage(method.Input()), dynamicpb.NewMessage(method.Output())
    pattern := method.Input().Fields().ByName("pattern")
    reset := method.Input().Fields().ByName("reset")
    check(pattern != nil && reset != nil, "QueryStats request fields missing")
    input.Set(pattern, protoreflect.ValueOfString(counterName))
    input.Set(reset, protoreflect.ValueOfBool(false))
    must0(r.conn.Invoke(r.ctx, "/"+string(service.FullName())+"/"+string(method.Name()), input, output))
    field := method.Output().Fields().ByName("stat")
    check(field != nil && field.IsList(), "QueryStats response stat field missing")
    list := output.Get(field).List()
    check(list.Len() == 1, "dynamic QueryStats returned %d counters", list.Len())
    stat := list.Get(0).Message()
    name, value := stat.Descriptor().Fields().ByName("name"), stat.Descriptor().Fields().ByName("value")
    check(name != nil && value != nil && stat.Get(name).String() == counterName && stat.Get(value).Int() == counterValue, "dynamic QueryStats counter name/value differs")
    r.result.DynamicQueries++
    r.result.DynamicValue = stat.Get(value).Int()
    r.result.Checks = append(r.result.Checks, "dynamic_canonical_query_stats")
}

func (r *runner) probe(profile string) result {
    r.result = result{Services:[]string{}, HandlerFiles:[]string{}, Checks:[]string{}, LookupErrors:[]lookupObservation{}, Streams:[]streamObservation{}}
    if profile == "disabled" {
        stream := r.open(r.ctx)
        err := stream.Send(&v1.ServerReflectionRequest{Host:echoHost, MessageRequest:&v1.ServerReflectionRequest_ListServices{}})
        check(err == nil || err == io.EOF, "disabled service Send: %v", err)
        response, err := stream.Recv()
        check(response == nil && status.Code(err) == codes.Unimplemented, "disabled reflection must terminate with status 12, got %v", err)
        observed := r.observe(stream, "disabled", err)
        _ = stream.CloseSend()
        r.result.TerminalCode = observed.Code
        r.result.Checks = append(r.result.Checks, "disabled_reflection_terminal_12")
        return r.result
    }
    expected := visible(profile)
    handler := must(protoregistry.GlobalFiles.FindDescriptorByName(handlerSymbol)).ParentFile()
    check(len(closure(handler)) == 4, "pinned Handler descriptor closure is not four files")
    stream, cache := r.open(r.ctx), make(descriptorCache)
    r.list(stream, expected)
    r.result.Services = expected
    r.files(stream, symbol(handlerSymbol), handler, cache)
    r.files(stream, filename(handler.Path()), handler, cache)
    r.files(stream, symbol(handlerSymbol+".AddInbound"), handler, cache)
    r.files(stream, symbol("xray.app.proxyman.command.AddInboundRequest"), handler, cache)
    dependency := must(protoregistry.GlobalFiles.FindDescriptorByName("xray.core.Config")).ParentFile()
    r.files(stream, filename(dependency.Path()), dependency, cache)
    r.result.Checks = append(r.result.Checks, "sorted_service_visibility", "handler_four_file_fresh_registry", "repeated_root_dependencies_once")
    for _, missing := range []struct { name string; request *v1.ServerReflectionRequest }{
        {"missing_filename", filename("missing/reflection-reference.proto")},
        {"missing_symbol", symbol("missing.reflection.Reference")},
        {"missing_extension", extension(999999)},
        {"missing_type", numbers("missing.reflection.Type")},
        {"legacy_alias_symbol", symbol("v2ray.core.app.proxyman.command.HandlerService")},
    } {
        response := r.ask(stream, missing.request)
        failure := response.GetErrorResponse()
        check(failure != nil && failure.GetErrorCode() == int32(codes.NotFound) && failure.GetErrorMessage() != "", "missing query must be in-message code 5: %v", response)
        r.result.LookupErrors = append(r.result.LookupErrors, lookupObservation{
            Query:missing.name, Code:failure.GetErrorCode(), Message:failure.GetErrorMessage(),
        })
        r.result.NotFound++
        r.list(stream, expected)
    }
    r.result.Checks = append(r.result.Checks, "missing_code_5_then_recovery")
    response := r.ask(stream, numbers("google.protobuf.FeatureSet"))
    extensionNumbers := response.GetAllExtensionNumbersResponse()
    check(extensionNumbers != nil && extensionNumbers.GetBaseTypeName() == "google.protobuf.FeatureSet" && slices.Equal(extensionNumbers.GetExtensionNumber(), []int32{1002}), "FeatureSet extension numbers differ: %v", response)
    goExtension := gofeaturespb.E_Go.TypeDescriptor()
    check(goExtension.Number() == 1002 && goExtension.ContainingMessage().FullName() == "google.protobuf.FeatureSet", "wrong pinned Go feature extension")
    extensionFile := goExtension.ParentFile()
    extensionRegistry := r.files(stream, extension(1002), extensionFile, cache)
    parsedExtension := must(extensionRegistry.FindDescriptorByName(goExtension.FullName())).(protoreflect.ExtensionDescriptor)
    check(parsedExtension.Number() == 1002 && parsedExtension.ContainingMessage().FullName() == "google.protobuf.FeatureSet", "reflected extension 1002 is not resolvable")
    r.files(stream, extension(1002), extensionFile, cache)
    r.result.Checks = append(r.result.Checks, "all_five_query_variants", "feature_set_extension_1002")
    statsFile := must(protoregistry.GlobalFiles.FindDescriptorByName(statsSymbol)).ParentFile()
    statsRegistry := r.files(stream, symbol(statsSymbol+".QueryStats"), statsFile, cache)
    if profile == "full" || profile == "stats" { r.dynamicStats(statsRegistry) }
    for _, name := range []string{"grpc.reflection.v1.ServerReflection", "grpc.reflection.v1alpha.ServerReflection"} {
        root := must(protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(name))).ParentFile()
        registry := r.files(stream, filename(root.Path()), root, cache)
        service := must(registry.FindDescriptorByName(protoreflect.FullName(name))).(protoreflect.ServiceDescriptor)
        method := service.Methods().ByName("ServerReflectionInfo")
        check(method != nil && method.IsStreamingClient() && method.IsStreamingServer(), "reflected reflection service must be bidirectional")
    }
    r.result.Checks = append(r.result.Checks, "both_reflection_schemas")
    r.finish(stream, "main")
    fresh := r.open(r.ctx)
    r.files(fresh, filename(handler.Path()), handler, make(descriptorCache))
    r.finish(fresh, "fresh")
    r.result.Checks = append(r.result.Checks, "fresh_stream_cache_reset")
    r.finish(r.open(r.ctx), "empty")
    r.result.EmptyEOF++
    r.result.Checks = append(r.result.Checks, "empty_stream_clean_eof")
    invalid := r.open(r.ctx)
    must0(invalid.Send(&v1.ServerReflectionRequest{Host:echoHost}))
    invalidResponse, err := invalid.Recv()
    check(invalidResponse == nil && status.Code(err) == codes.InvalidArgument, "missing oneof must terminate with status 3, got %v", err)
    invalidObserved := r.observe(invalid, "missing_oneof", err)
    _ = invalid.CloseSend()
    r.result.TerminalCode = invalidObserved.Code
    recovery := r.open(r.ctx)
    r.list(recovery, expected)
    r.finish(recovery, "missing_oneof_recovery")
    r.result.Checks = append(r.result.Checks, "missing_oneof_terminal_3_then_recovery")
    cancelledContext, cancel := context.WithCancel(r.ctx)
    defer cancel()
    cancelled, survivor := r.open(cancelledContext), r.open(r.ctx)
    r.files(cancelled, symbol(handlerSymbol), handler, make(descriptorCache))
    survivorCache := make(descriptorCache)
    r.files(survivor, filename(handler.Path()), handler, survivorCache)
    cancel()
    cancelledResponse, err := cancelled.Recv()
    check(cancelledResponse == nil && status.Code(err) == codes.Canceled, "cancelled stream must have status 1, got %v", err)
    r.result.CancelledCode = r.observe(cancelled, "cancelled", err).Code
    r.files(survivor, filename(handler.Path()), handler, survivorCache)
    r.list(survivor, expected)
    r.finish(survivor, "survivor")
    r.result.Checks = append(r.result.Checks, "cancellation_code_1_concurrent_isolation", "send_recv_before_close_send", "host_original_request_echo", "clean_eof_after_requests")
    check(r.result.Queries == 28 && r.result.Echoes == 28 && r.result.NotFound == 5 && r.result.FreshClosures == 4 && r.result.RepeatedRoots == 6 && r.result.CleanEOF == 5, "incomplete reflection scenario counts: %+v", r.result)
    check(len(r.result.LookupErrors) == 5 && len(r.result.Streams) == 7, "missing actual error/trailer observations: %+v", r.result)
    slices.Sort(r.result.Checks)
    return r.result
}

func baseline(c command) (string, *core.Instance) {
    // Commander has no bound-address accessor. Reserve a kernel-selected port,
    // release it immediately before core.Start, and fail explicitly on bind races.
    reservation := must(net.Listen("tcp4", c.Address))
    address := reservation.Addr().String()
    configuration := map[string]any{
        "api":map[string]any{"tag":"reflection-api", "listen":address, "services":services(c.Profile)},
        "stats":map[string]any{}, "routing":map[string]any{"rules":[]any{}},
        "observatory":map[string]any{"subjectSelector":[]string{}},
        "log":map[string]any{"loglevel":"none", "access":"none", "error":"none"},
    }
    var config conf.Config
    must0(json.Unmarshal(must(json.Marshal(configuration)), &config))
    instance := must(core.New(must(config.Build())))
    started := false
    defer func() { _ = reservation.Close(); if !started { _ = instance.Close() } }()
    manager, ok := instance.GetFeature(featurestats.ManagerType()).(featurestats.Manager)
    check(ok, "pinned configured stats manager absent")
    must(manager.RegisterCounter(counterName)).Set(counterValue)
    must0(reservation.Close())
    must0(instance.Start())
    check(instance.IsRunning(), "pinned core did not start")
    started = true
    return address, instance
}

func protobufVersion() string {
    info, ok := debug.ReadBuildInfo()
    check(ok, "missing module build information")
    for _, dependency := range info.Deps {
        if dependency.Path == "google.golang.org/protobuf" {
            check(dependency.Replace == nil, "protobuf replacement is not the locked dependency")
            return dependency.Version
        }
    }
    panic("missing protobuf dependency in build information")
}
func run() (err error) {
    defer func() { if failure := recover(); failure != nil { err = fmt.Errorf("reflection reference: %v", failure) } }()
    check(runtime.GOOS == "linux" && len(os.Args) == 1, "Linux only; pass one strict JSON control on stdin then EOF")
    check(grpc.Version == "1.85.0" && protobufVersion() == "v1.36.12" && strings.HasPrefix(runtime.Version(), "go1.27"), "requires locked grpc-go 1.85.0, protobuf 1.36.12 and Go 1.27")
    c := must(readCommand())
    ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.TimeoutMS)*time.Millisecond)
    defer cancel()
    address := c.Address
    if c.Mode == "baseline" {
        var instance *core.Instance
        address, instance = baseline(c)
        defer func() { if closeErr := instance.Close(); err == nil { err = closeErr } }()
    }
    direct := &net.Dialer{}
    var dial proxy.ContextDialer = direct
    if c.Socks != "" {
        socks := must(proxy.SOCKS5("tcp", c.Socks, nil, direct))
        var ok bool
        dial, ok = socks.(proxy.ContextDialer)
        check(ok, "locked x/net SOCKS5 dialer has no context cancellation")
    }
    connection := must(grpc.NewClient("passthrough:///"+address,
        grpc.WithTransportCredentials(insecure.NewCredentials()),
        grpc.WithAuthority("api-reflection.reference.invalid"),
        grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return dial.DialContext(ctx, "tcp", address) }),
        grpc.WithDisableRetry()))
    defer connection.Close()
    r := runner{ctx:ctx, conn:connection, version:c.Version}
    outcome := r.probe(c.Profile)
    return json.NewEncoder(os.Stdout).Encode(event{Event:"done", Reference:reference, GRPCVersion:grpc.Version,
        ProtobufVersion:protobufVersion(), GoVersion:runtime.Version(), Mode:c.Mode, Address:address, Socks:c.Socks,
        Version:c.Version, Profile:c.Profile, Result:outcome})
}
func main() {
    log.RegisterHandler(log.NewLogger(log.CreateStderrLogWriter()))
    watchdog := time.AfterFunc(15*time.Second, func() { fmt.Fprintln(os.Stderr, "reflection peer exceeded 15s deadline"); os.Exit(1) })
    defer watchdog.Stop()
    if err := run(); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}
