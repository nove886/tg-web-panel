package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testConfig(target string) Config {
	return Config{Domain:"tg.test.net", Target:target, TrustedCIDRs:[]string{"173.245.48.0/20"}, HealthToken:"test-health"}
}

func TestForwardingPreservesProtocolAndNormalizesIP(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "tg.test.net" { t.Errorf("host: %s", r.Host) }
		if r.Header.Get("X-Forwarded-For") != "203.0.113.21" { t.Errorf("xff: %q", r.Header.Get("X-Forwarded-For")) }
		if r.Header.Get("Forwarded") != "" || r.Header.Get("X-Panel-Client-IP") != "" { t.Error("untrusted headers leaked") }
		if r.Header.Get("Authorization") != "Bearer sample" { t.Error("auth lost") }
		if r.URL.RawQuery != "bridge=abc&bridge=def" { t.Error("query was changed") }
		if r.Header.Get("X-Up-Seq") != "1" { t.Error("sequence lost") }
		body, _ := io.ReadAll(r.Body)
		if string(body) != "\x00\x01\xff" { t.Error("binary data changed") }
		w.Header().Set("X-Down-Cursor", "7")
		w.Write(body)
	}))
	defer target.Close()
	h, err := handler(testConfig(target.URL)); if err != nil { t.Fatal(err) }
	r := httptest.NewRequest("POST", "https://tg.test.net/api/v1/up?bridge=abc&bridge=def", strings.NewReader("\x00\x01\xff"))
	r.RemoteAddr = "173.245.48.5:1234"
	r.Header.Set("CF-Connecting-IP", "203.0.113.21")
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	r.Header.Set("X-Panel-Client-IP", "8.8.8.8")
	r.Header.Set("Forwarded", "for=attacker")
	r.Header.Set("Authorization", "Bearer sample")
	r.Header.Set("X-Up-Seq", "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("X-Down-Cursor") != "7" || w.Body.String() != "\x00\x01\xff" { t.Fatalf("bad response: %v", w) }
}

func TestUntrustedOrMalformedPeersRejected(t *testing.T) {
	h, err := handler(testConfig("http://127.0.0.1:1")); if err != nil { t.Fatal(err) }
	for _, tc := range []struct{peer, host, client string}{
		{"203.0.113.5:1234", "tg.test.net", "1.1.1.1"},
		{"173.245.48.5:1234", "wrong.test.net", "1.1.1.1"},
		{"173.245.48.5:1234", "tg.test.net", "1.1.1.1, 8.8.8.8"},
		{"173.245.48.5:1234", "tg.test.net", ""},
	} {
		r := httptest.NewRequest("GET", "https://"+tc.host+"/", nil)
		r.RemoteAddr = tc.peer
		r.Header.Set("CF-Connecting-IP", tc.client)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 404 { t.Errorf("%v: got %d", tc, w.Code) }
	}
}

func TestLocalHealthAndLoopbackOnlyBackend(t *testing.T) {
	h, err := handler(testConfig("http://127.0.0.1:1")); if err != nil { t.Fatal(err) }
	r := httptest.NewRequest("GET", "https://tg.test.net/.well-known/panel-check/test-health", nil)
	r.RemoteAddr = "127.0.0.1:1000"
	w := httptest.NewRecorder(); h.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "test-health" || w.Header().Get("Cache-Control") != "no-store" { t.Fatal("bad health response") }
	for _, target := range []string{"http://example.com:80", "http://10.0.0.1:1234", "https://127.0.0.1:80"} {
		if _, err := handler(testConfig(target)); err == nil { t.Errorf("accepted target %s", target) }
	}
}

func TestWebsocketUpgradeIsBidirectional(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil { t.Error(err); return }
		defer conn.Close()
		buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		buffered.Flush()
		data := make([]byte, 4)
		if _, err := io.ReadFull(buffered, data); err != nil { t.Error(err); return }
		buffered.Write(data); buffered.Flush()
	}))
	defer target.Close()
	h, err := handler(testConfig(target.URL)); if err != nil { t.Fatal(err) }
	front := httptest.NewServer(h); defer front.Close()
	conn, err := net.Dial("tcp", front.Listener.Addr().String()); if err != nil { t.Fatal(err) }
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5*time.Second))
	io.WriteString(conn, "GET /api/v1/ws HTTP/1.1\r\nHost: tg.test.net\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil); if err != nil { t.Fatal(err) }
	if response.StatusCode != 101 { t.Fatalf("got %d", response.StatusCode) }
	conn.Write([]byte{0,1,2,255})
	data := make([]byte, 4)
	if _, err := io.ReadFull(reader, data); err != nil { t.Fatal(err) }
	if string(data) != "\x00\x01\x02\xff" { t.Fatal("websocket bytes changed") }
}

func TestCertificateCreatedAndReused(t *testing.T) {
	dir := t.TempDir()
	c := testConfig("http://127.0.0.1:1")
	c.SelfSigned = true
	c.CertFile = filepath.Join(dir, "origin.pem")
	c.KeyFile = filepath.Join(dir, "origin.key")
	if err := ensureCertificate(c); err != nil { t.Fatal(err) }
	one, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile); if err != nil { t.Fatal(err) }
	crt, err := x509.ParseCertificate(one.Certificate[0]); if err != nil { t.Fatal(err) }
	if err := crt.VerifyHostname(c.Domain); err != nil { t.Fatal(err) }
	if err := ensureCertificate(c); err != nil { t.Fatal(err) }
	two, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile); if err != nil { t.Fatal(err) }
	if string(one.Certificate[0]) != string(two.Certificate[0]) { t.Fatal("unnecessary certificate rotation") }
}
