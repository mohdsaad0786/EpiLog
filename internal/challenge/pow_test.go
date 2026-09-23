package challenge

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestProofAndBinding(t *testing.T) {
	service, err := New("0123456789abcdef0123456789abcdef", 1)
	if err != nil {
		t.Fatal(err)
	}
	page := httptest.NewRecorder()
	service.Present(page, "192.0.2.10")
	token := regexp.MustCompile(`name="token" type="hidden" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
	if len(token) != 2 {
		t.Fatal("challenge token missing")
	}
	proof := ""
	for nonce := 0; nonce < 256; nonce++ {
		candidate := strconv.Itoa(nonce)
		digest := sha256.Sum256([]byte(token[1] + candidate))
		if strings.HasPrefix(hex.EncodeToString(digest[:]), "0") {
			proof = candidate
			break
		}
	}
	if proof == "" {
		t.Fatal("proof unavailable")
	}
	form := url.Values{"token": {token[1]}, "nonce": {proof}}
	request := httptest.NewRequest("POST", "http://localhost/__bhai/solve", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	service.Solve(response, request, "192.0.2.10")
	if response.Code != 303 {
		t.Fatalf("expected clearance, got %d", response.Code)
	}
	cleared := httptest.NewRequest("GET", "http://localhost/", nil)
	for _, cookie := range response.Result().Cookies() {
		cleared.AddCookie(cookie)
	}
	if !service.Cleared(cleared, "192.0.2.10") || service.Cleared(cleared, "192.0.2.11") {
		t.Fatal("clearance not bound to peer IP")
	}
}
