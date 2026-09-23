package proxy

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mohdsaad0786/EpiLog/internal/challenge"
	"github.com/mohdsaad0786/EpiLog/internal/ratelimit"
	"github.com/mohdsaad0786/EpiLog/internal/rules"
	"github.com/mohdsaad0786/EpiLog/internal/story"
	"github.com/mohdsaad0786/EpiLog/internal/threat"
	"github.com/prometheus/client_golang/prometheus"
)

type Proxy struct {
	upstream       *httputil.ReverseProxy
	rules          *rules.Engine
	stories        *story.Engine
	limiter        *ratelimit.Limiter
	threat         *threat.Reputation
	challenge      *challenge.Service
	maxBody        int64
	total          *prometheus.CounterVec
	latency        prometheus.Histogram
	threatHits     *prometheus.CounterVec
	challenges     prometheus.Counter
	torCount       atomic.Uint64
	vpnCount       atomic.Uint64
	challengeCount atomic.Uint64
}

func New(target string, engine *rules.Engine, stories *story.Engine, limiter *ratelimit.Limiter, threat *threat.Reputation, challenge *challenge.Service, maxBody int64, register prometheus.Registerer) (*Proxy, error) {
	address, err := url.Parse(target)
	if err != nil || !(address.Scheme == "http" || address.Scheme == "https") || address.Host == "" {
		return nil, io.ErrUnexpectedEOF
	}
	upstream := httputil.NewSingleHostReverseProxy(address)
	upstream.Transport = &http.Transport{Proxy: http.ProxyFromEnvironment, MaxIdleConns: 100, MaxIdleConnsPerHost: 20, IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	result := &Proxy{upstream: upstream, rules: engine, stories: stories, limiter: limiter, threat: threat, challenge: challenge, maxBody: maxBody, total: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "bhai_requests_total", Help: "Requests observed by the WAF."}, []string{"action"}), latency: prometheus.NewHistogram(prometheus.HistogramOpts{Name: "bhai_request_seconds", Help: "WAF plus upstream request duration.", Buckets: prometheus.DefBuckets}), threatHits: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "bhai_threat_hits_total", Help: "Requests from detected Tor/VPN peers."}, []string{"type"}), challenges: prometheus.NewCounter(prometheus.CounterOpts{Name: "bhai_challenges_total", Help: "Proof-of-work challenges issued."})}
	register.MustRegister(result.total, result.latency, result.threatHits, result.challenges)
	return result, nil
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (writer *responseRecorder) WriteHeader(status int) {
	if writer.status != 0 {
		return
	}
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}
func (writer *responseRecorder) Write(content []byte) (int, error) {
	if writer.status == 0 {
		writer.WriteHeader(200)
	}
	count, err := writer.ResponseWriter.Write(content)
	writer.bytes += count
	return count, err
}
func (writer *responseRecorder) Flush() {
	if flush, ok := writer.ResponseWriter.(http.Flusher); ok {
		flush.Flush()
	}
}
func (proxy *Proxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	started := time.Now()
	record := &responseRecorder{ResponseWriter: writer}
	ip, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		http.Error(record, "invalid peer", 400)
		return
	}
	if request.URL.Path == "/__bhai/solve" {
		proxy.challenge.Solve(record, request, ip)
		return
	}
	userAgent := request.UserAgent()
	if len(userAgent) > 256 {
		userAgent = userAgent[:256]
	}
	action, reason, category, severity := "allowed", "", "", ""
	typeName := proxy.threat.Lookup(ip)
	if typeName != "" {
		proxy.threatHits.WithLabelValues(typeName).Inc()
		if typeName == "tor" {
			proxy.torCount.Add(1)
		} else {
			proxy.vpnCount.Add(1)
		}
	}
	if proxy.stories != nil && proxy.stories.IsBlocked(ip) {
		action, reason = "blocked", "auto-block"
	} else if !proxy.limiter.Allow(ip) {
		action, reason = "blocked", "rate-limit"
	} else if request.ContentLength > proxy.maxBody {
		action, reason = "blocked", "oversized-body"
	} else {
		body, readErr := io.ReadAll(io.LimitReader(request.Body, proxy.maxBody+1))
		if readErr != nil {
			http.Error(record, "bad body", 400)
			return
		}
		if int64(len(body)) > proxy.maxBody {
			action, reason = "blocked", "oversized-body"
		} else {
			request.Body = io.NopCloser(bytes.NewReader(body))
			request.ContentLength = int64(len(body))
			query := request.URL.RawQuery
			for key, values := range request.URL.Query() {
				query += " " + key + " " + strings.Join(values, " ")
			}
			match := proxy.rules.Evaluate(rules.Input{Path: request.URL.EscapedPath() + " " + request.URL.Path, Query: query, Body: string(body), Headers: headers(request.Header), UserAgent: request.UserAgent()})
			if match.Matched {
				reason, category, severity = match.RuleID, match.Category, match.Severity
				switch match.Action {
				case "block":
					action = "blocked"
				case "challenge":
					action = "challenged"
				}
			}
			if action == "allowed" && typeName != "" && !proxy.challenge.Cleared(request, ip) {
				action, reason = "challenged", typeName
			}
			if action == "allowed" && proxy.stories != nil && proxy.stories.Verdict(ip, userAgent, "") == "medium" && !proxy.challenge.Cleared(request, ip) {
				action, reason = "challenged", "session-score"
			}
			if action == "challenged" && proxy.challenge.Cleared(request, ip) {
				action = "allowed"
			}
		}
	}
	switch action {
	case "blocked":
		if reason == "rate-limit" {
			record.Header().Set("Retry-After", "1")
			http.Error(record, "rate limited", 429)
		} else if reason == "oversized-body" {
			http.Error(record, "request too large", 413)
		} else {
			http.Error(record, "blocked by Bhai WAF", 403)
		}
	case "challenged":
		proxy.challenges.Inc()
		proxy.challengeCount.Add(1)
		proxy.challenge.Present(record, ip)
	default:
		proxy.upstream.ServeHTTP(record, request)
	}
	if record.status == 0 {
		record.status = 200
	}
	proxy.total.WithLabelValues(action).Inc()
	proxy.latency.Observe(time.Since(started).Seconds())
	if proxy.stories != nil {
		result := proxy.stories.Observe(story.Observation{IP: ip, UserAgent: userAgent, Method: request.Method, Path: redactPath(request.URL), Status: record.status, Action: action, Reason: reason, Category: category, Severity: severity, ResponseBytes: record.bytes, TorVPN: typeName != "", Latency: time.Since(started), At: started})
		if result.Verdict == "high" {
			proxy.stories.Block(ip, time.Hour)
		}
	}
}
func (proxy *Proxy) Stats() map[string]uint64 {
	return map[string]uint64{"tor": proxy.torCount.Load(), "vpn": proxy.vpnCount.Load(), "challenges": proxy.challengeCount.Load()}
}
func redactPath(address *url.URL) string {
	copyURL := *address
	query := copyURL.Query()
	for key := range query {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "auth") || strings.Contains(lower, "api_key") {
			query.Set(key, "[redacted]")
		}
	}
	copyURL.RawQuery = query.Encode()
	result := copyURL.RequestURI()
	if len(result) > 2048 {
		return result[:2048]
	}
	return result
}
func headers(header http.Header) string {
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var value strings.Builder
	for _, key := range keys {
		if strings.EqualFold(key, "cookie") || strings.EqualFold(key, "authorization") {
			continue
		}
		for _, entry := range header[key] {
			if value.Len()+len(entry) > 8192 {
				return value.String()
			}
			value.WriteString(key)
			value.WriteByte(':')
			value.WriteString(entry)
			value.WriteByte('\n')
		}
	}
	return value.String()
}
