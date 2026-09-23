package threat

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Reputation struct {
	mu     sync.RWMutex
	tor    map[string]bool
	vpn    []*net.IPNet
	source string
	client *http.Client
}

func New(source string, cidrs []string) (*Reputation, error) {
	result := &Reputation{tor: make(map[string]bool), source: source, client: &http.Client{Timeout: 8 * time.Second}}
	for _, text := range cidrs {
		_, network, err := net.ParseCIDR(text)
		if err != nil {
			return nil, fmt.Errorf("vpn CIDR %q: %w", text, err)
		}
		result.vpn = append(result.vpn, network)
	}
	return result, nil
}
func (reputation *Reputation) Lookup(ip string) string {
	address := net.ParseIP(ip)
	if address == nil {
		return ""
	}
	reputation.mu.RLock()
	defer reputation.mu.RUnlock()
	if reputation.tor[address.String()] {
		return "tor"
	}
	for _, network := range reputation.vpn {
		if network.Contains(address) {
			return "vpn"
		}
	}
	return ""
}
func (reputation *Reputation) Refresh(ctx context.Context) error {
	if reputation.source == "" {
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, "GET", reputation.source, nil)
	if err != nil {
		return err
	}
	response, err := reputation.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("tor feed returned %d", response.StatusCode)
	}
	loaded := make(map[string]bool)
	scanner := bufio.NewScanner(io.LimitReader(response.Body, 4<<20))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if address := net.ParseIP(line); address != nil {
			loaded[address.String()] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(loaded) == 0 {
		return fmt.Errorf("tor feed empty")
	}
	reputation.mu.Lock()
	reputation.tor = loaded
	reputation.mu.Unlock()
	return nil
}
