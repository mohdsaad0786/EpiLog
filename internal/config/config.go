package config

import (
	"bytes"
	"errors"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen       string `yaml:"listen"`
	Dashboard    string `yaml:"dashboard"`
	Upstream     string `yaml:"upstream"`
	Database     string `yaml:"database"`
	RulesDir     string `yaml:"rules_dir"`
	MaxBodyBytes int64  `yaml:"max_body_bytes"`
	RateLimit    struct {
		Rate  float64 `yaml:"rate"`
		Burst int     `yaml:"burst"`
	} `yaml:"rate_limit"`
	Story struct {
		Enabled            bool          `yaml:"enabled"`
		Window             time.Duration `yaml:"window"`
		Retention          time.Duration `yaml:"retention"`
		AutoBlockThreshold int           `yaml:"auto_block_threshold"`
		AutoBlockDuration  time.Duration `yaml:"auto_block_duration"`
	} `yaml:"story"`
	Threat struct {
		TorURL   string   `yaml:"tor_url"`
		VPNCIDRs []string `yaml:"vpn_cidrs"`
	} `yaml:"threat"`
	Challenge struct {
		Secret     string `yaml:"secret"`
		Difficulty int    `yaml:"difficulty"`
	} `yaml:"challenge"`
}

func Load(path string) (Config, error) {
	config := Config{Listen: "127.0.0.1:8080", Dashboard: "127.0.0.1:9090", Upstream: "http://127.0.0.1:3000", Database: "bhai-waf.db", MaxBodyBytes: 1 << 20}
	config.RateLimit.Rate, config.RateLimit.Burst = 10, 30
	config.Story.Enabled, config.Story.Window, config.Story.Retention = true, 5*time.Minute, 30*24*time.Hour
	config.Story.AutoBlockThreshold, config.Story.AutoBlockDuration = 86, 24*time.Hour
	config.Challenge.Difficulty = 4
	config.Threat.TorURL = "https://check.torproject.org/torbulkexitlist"
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return config, err
		}
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&config); err != nil {
			return config, err
		}
	}
	if config.RateLimit.Rate <= 0 || config.RateLimit.Burst <= 0 || config.MaxBodyBytes <= 0 || config.Story.Window <= 0 || config.Story.Retention <= 0 || config.Story.AutoBlockDuration <= 0 || config.Story.AutoBlockThreshold < 1 || config.Story.AutoBlockThreshold > 100 || config.Challenge.Difficulty < 1 || config.Challenge.Difficulty > 6 {
		return config, errors.New("invalid limits or durations in configuration")
	}
	return config, nil
}
