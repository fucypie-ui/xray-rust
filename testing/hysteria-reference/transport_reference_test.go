package hysteria

import (
    "encoding/json"
    "fmt"
    "net/http/httptest"
    "testing"
    "github.com/xtls/xray-core/transport/internet"
)

func TestRustReferenceVectors(t *testing.T) {
    type vector struct { Method string `json:"method"`; URL string `json:"url"`; Auth string `json:"auth"`; Accepted bool `json:"accepted"`; Status int `json:"status"`; UDP string `json:"udp"`; RX string `json:"rx"` }
    vectors := []vector{}
    for _, v := range []vector{
        {Method:"POST", URL:"https://hysteria/auth", Auth:"secret"},
        {Method:"POST", URL:"https://hysteria/auth", Auth:"wrong"},
        {Method:"GET", URL:"https://hysteria/auth", Auth:"secret"},
        {Method:"POST", URL:"https://other/auth", Auth:"secret"},
        {Method:"POST", URL:"https://hysteria/nope", Auth:"secret"},
    } {
        h := &httpHandler{config: &Config{Auth: "secret"}, quicParams: &internet.QuicParams{Congestion: "reno", BrutalDown: 123456}}
        request := httptest.NewRequest(v.Method, v.URL, nil)
        request.Header.Set(RequestHeaderAuth, v.Auth)
        response := httptest.NewRecorder()
        v.Accepted = h.AuthHTTP(response, request)
        if v.Accepted { v.Status = response.Code } else { v.Status = 404 }
        v.UDP, v.RX = response.Header().Get(ResponseHeaderUDPEnabled), response.Header().Get(CommonHeaderCCRX)
        vectors = append(vectors, v)
    }
    b, err := json.Marshal(map[string]interface{}{"kind":"authentication", "vectors":vectors}); if err != nil { t.Fatal(err) }
    fmt.Printf("HYSTERIA_VECTOR %s\n", b)
}
