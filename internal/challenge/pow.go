package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Service struct {
	secret     []byte
	difficulty int
}

func New(secret string, difficulty int) (*Service, error) {
	key := []byte(secret)
	if secret == "" {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
	}
	if len(key) < 16 {
		return nil, fmt.Errorf("challenge secret must contain at least 16 bytes")
	}
	return &Service{key, difficulty}, nil
}
func (service *Service) sign(raw string) string {
	digest := hmac.New(sha256.New, service.secret)
	digest.Write([]byte(raw))
	return base64.RawURLEncoding.EncodeToString([]byte(raw)) + "." + base64.RawURLEncoding.EncodeToString(digest.Sum(nil))
}
func (service *Service) verify(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	expected := hmac.New(sha256.New, service.secret)
	expected.Write(raw)
	return string(raw), hmac.Equal(expected.Sum(nil), signature)
}
func (service *Service) Cleared(request *http.Request, ip string) bool {
	cookie, err := request.Cookie("bhai_clearance")
	if err != nil {
		return false
	}
	raw, valid := service.verify(cookie.Value)
	if !valid {
		return false
	}
	parts := strings.Split(raw, "|")
	if len(parts) != 2 || parts[0] != ip {
		return false
	}
	expiry, err := strconv.ParseInt(parts[1], 10, 64)
	return err == nil && time.Now().Unix() < expiry
}
func (service *Service) Present(writer http.ResponseWriter, ip string) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(writer, "challenge unavailable", 503)
		return
	}
	token := service.sign(fmt.Sprintf("%s|%d|%s", ip, time.Now().Add(2*time.Minute).Unix(), hex.EncodeToString(nonce)))
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
	writer.WriteHeader(http.StatusForbidden)
	_ = page.Execute(writer, struct {
		Token      string
		Difficulty int
	}{token, service.difficulty})
}
func (service *Service) Solve(writer http.ResponseWriter, request *http.Request, ip string) {
	if request.Method != "POST" {
		http.Error(writer, "method not allowed", 405)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 4096)
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "bad form", 400)
		return
	}
	token, nonce := request.Form.Get("token"), request.Form.Get("nonce")
	raw, valid := service.verify(token)
	parts := strings.Split(raw, "|")
	if !valid || len(parts) != 3 || parts[0] != ip || len(nonce) > 32 {
		http.Error(writer, "invalid challenge", 403)
		return
	}
	expiry, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		http.Error(writer, "expired challenge", 403)
		return
	}
	digest := sha256.Sum256([]byte(token + nonce))
	if !strings.HasPrefix(hex.EncodeToString(digest[:]), strings.Repeat("0", service.difficulty)) {
		http.Error(writer, "invalid proof", 403)
		return
	}
	http.SetCookie(writer, &http.Cookie{Name: "bhai_clearance", Value: service.sign(fmt.Sprintf("%s|%d", ip, time.Now().Add(time.Hour).Unix())), Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: request.TLS != nil, MaxAge: 3600})
	writer.Header().Set("Cache-Control", "no-store")
	http.Redirect(writer, request, "/", http.StatusSeeOther)
}

var page = template.Must(template.New("challenge").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Bhai WAF verification</title><meta name="viewport" content="width=device-width"><main><h1>Checking your browser</h1><p>Solving a short proof of work to protect this site.</p><p id="status">Working…</p><form id="verify" method="post" action="/__bhai/solve"><input name="token" type="hidden" value="{{.Token}}"><input name="nonce" type="hidden"></form></main><script>const token={{.Token}}, difficulty={{.Difficulty}};async function run(){let n=0;for(;;){const hash=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token+String(n)));const bytes=new Uint8Array(hash);const hex=Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');if(hex.startsWith('0'.repeat(difficulty))){document.querySelector('[name=nonce]').value=String(n);document.querySelector('#verify').submit();return}n++;if(n%500===0)document.querySelector('#status').textContent='Checking… '+n}}run().catch(()=>document.querySelector('#status').textContent='Verification requires a secure browser context.');</script></html>`))
