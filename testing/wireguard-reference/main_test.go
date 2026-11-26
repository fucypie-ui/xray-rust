package main

import (
    "bytes"
    "encoding/json"
    "io"
    "os"
    "strings"
    "testing"
)

func TestDeviceErrorsLeaveStdoutAsStrictReadinessJSON(t *testing.T) {
    reader, writer, err := os.Pipe()
    if err != nil { t.Fatal(err) }
    defer reader.Close()
    original := os.Stdout
    os.Stdout = writer
    defer func() { os.Stdout = original; writer.Close() }()
    var diagnostics bytes.Buffer
    referenceLogger(&diagnostics).Errorf("Failed to send handshake initiation: %s", "no known endpoint for peer")
    emit(map[string]any{"endpoint": "127.0.0.1:51820", "publicKey": public(bobSecret)})
    if err := writer.Close(); err != nil { t.Fatal(err) }
    output, err := io.ReadAll(reader)
    if err != nil { t.Fatal(err) }
    var ready struct { Endpoint string `json:"endpoint"`; PublicKey string `json:"publicKey"` }
    if err := json.Unmarshal(output, &ready); err != nil { t.Fatalf("stdout must contain only JSON: %v: %q", err, output) }
    if ready.Endpoint != "127.0.0.1:51820" || ready.PublicKey != public(bobSecret) { t.Fatalf("incorrect readiness: %+v", ready) }
    if !strings.Contains(diagnostics.String(), "no known endpoint for peer") { t.Fatal("device error diagnostic was lost") }
}
