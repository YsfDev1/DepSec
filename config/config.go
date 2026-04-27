package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config represents SecChain configuration
type Config struct {
	// General settings
	Mode        string `toml:"mode"`         // interactive, strict, log
	MinSeverity string `toml:"min_severity"` // low, medium, high, critical
	Offline     bool   `toml:"offline"`

	// Auto-scan settings
	AutoScan struct {
		Enabled    bool     `toml:"enabled"`
		Ecosystems []string `toml:"ecosystems"` // node, python, rust, go, ruby
	} `toml:"auto_scan"`

	// Docker settings
	Docker struct {
		Enabled bool   `toml:"enabled"`
		Image   string `toml:"image"`
		Timeout int    `toml:"timeout"` // seconds
	} `toml:"docker"`

	// ClamAV settings
	ClamAV struct {
		Enabled bool   `toml:"enabled"`
		Socket  string `toml:"socket"`
	} `toml:"clamav"`

	// YARA settings
	YARA struct {
		Enabled     bool     `toml:"enabled"`
		RulesPath   string   `toml:"rules_path"`
		CustomRules []string `toml:"custom_rules"`
	} `toml:"yara"`

	// Cache settings
	Cache struct {
		Enabled bool `toml:"enabled"`
		TTL     int  `toml:"ttl"` // hours
	} `toml:"cache"`

	// Output settings
	Output struct {
		Format    string `toml:"format"` // table, json, minimal
		ShowClean bool   `toml:"show_clean"`
		Verbose   bool   `toml:"verbose"`
	} `toml:"output"`
}

// Manager handles configuration operations
type Manager struct {
	configPath string
	config     *Config
}

// NewManager creates a new configuration manager
func NewManager() (*Manager, error) {
	configDir := getConfigDir()
	configPath := filepath.Join(configDir, "config.toml")

	manager := &Manager{
		configPath: configPath,
	}

	// Load existing config or create default
	if err := manager.load(); err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	return manager, nil
}

// load loads configuration from file or creates default
func (m *Manager) load() error {
	// Create config directory if it doesn't exist
	configDir := filepath.Dir(m.configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Check if config file exists
	if _, err := os.Stat(m.configPath); os.IsNotExist(err) {
		// Create default config
		m.config = m.getDefaultConfig()
		return m.save()
	}

	// Load existing config
	m.config = &Config{}
	_, err := toml.DecodeFile(m.configPath, m.config)
	if err != nil {
		return fmt.Errorf("failed to decode config file: %w", err)
	}

	return nil
}

// getDefaultConfig returns the default configuration
func (m *Manager) getDefaultConfig() *Config {
	return &Config{
		Mode:        "interactive",
		MinSeverity: "medium",
		Offline:     false,
		AutoScan: struct {
			Enabled    bool     `toml:"enabled"`
			Ecosystems []string `toml:"ecosystems"`
		}{
			Enabled:    false,
			Ecosystems: []string{"node", "python", "rust", "go", "ruby"},
		},
		Docker: struct {
			Enabled bool   `toml:"enabled"`
			Image   string `toml:"image"`
			Timeout int    `toml:"timeout"`
		}{
			Enabled: true,
			Image:   "secchain/scanner:latest",
			Timeout: 300,
		},
		ClamAV: struct {
			Enabled bool   `toml:"enabled"`
			Socket  string `toml:"socket"`
		}{
			Enabled: true,
			Socket:  "/var/run/clamav/clamd.sock",
		},
		YARA: struct {
			Enabled     bool     `toml:"enabled"`
			RulesPath   string   `toml:"rules_path"`
			CustomRules []string `toml:"custom_rules"`
		}{
			Enabled:   true,
			RulesPath: filepath.Join(getConfigDir(), "rules"),
		},
		Cache: struct {
			Enabled bool `toml:"enabled"`
			TTL     int  `toml:"ttl"`
		}{
			Enabled: true,
			TTL:     24,
		},
		Output: struct {
			Format    string `toml:"format"`
			ShowClean bool   `toml:"show_clean"`
			Verbose   bool   `toml:"verbose"`
		}{
			Format:    "table",
			ShowClean: true,
			Verbose:   false,
		},
	}
}

// save saves configuration to file
func (m *Manager) save() error {
	file, err := os.Create(m.configPath)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()

	encoder := toml.NewEncoder(file)
	if err := encoder.Encode(m.config); err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}

	return nil
}

// Get returns the current configuration
func (m *Manager) Get() *Config {
	return m.config
}

// Set updates a configuration value
func (m *Manager) Set(key, value string) error {
	switch key {
	case "mode":
		m.config.Mode = value
	case "min_severity":
		m.config.MinSeverity = value
	case "offline":
		m.config.Offline = value == "true"
	case "auto_scan.enabled":
		m.config.AutoScan.Enabled = value == "true"
	case "docker.enabled":
		m.config.Docker.Enabled = value == "true"
	case "clamav.enabled":
		m.config.ClamAV.Enabled = value == "true"
	case "yara.enabled":
		m.config.YARA.Enabled = value == "true"
	case "cache.enabled":
		m.config.Cache.Enabled = value == "true"
	case "output.format":
		m.config.Output.Format = value
	case "output.show_clean":
		m.config.Output.ShowClean = value == "true"
	case "output.verbose":
		m.config.Output.Verbose = value == "true"
	default:
		return fmt.Errorf("unknown configuration key: %s", key)
	}

	return m.save()
}

// Reset resets configuration to defaults
func (m *Manager) Reset() error {
	m.config = m.getDefaultConfig()
	return m.save()
}

// Show displays the current configuration
func (m *Manager) Show() map[string]interface{} {
	return map[string]interface{}{
		"mode":         m.config.Mode,
		"min_severity": m.config.MinSeverity,
		"offline":      m.config.Offline,
		"auto_scan":    m.config.AutoScan,
		"docker":       m.config.Docker,
		"clamav":       m.config.ClamAV,
		"yara":         m.config.YARA,
		"cache":        m.config.Cache,
		"output":       m.config.Output,
	}
}

// Validate validates the current configuration
func (m *Manager) Validate() error {
	// Validate mode
	validModes := []string{"interactive", "strict", "log"}
	if !contains(validModes, m.config.Mode) {
		return fmt.Errorf("invalid mode: %s (must be one of: %v)", m.config.Mode, validModes)
	}

	// Validate severity
	validSeverities := []string{"low", "medium", "high", "critical"}
	if !contains(validSeverities, m.config.MinSeverity) {
		return fmt.Errorf("invalid min_severity: %s (must be one of: %v)", m.config.MinSeverity, validSeverities)
	}

	// Validate output format
	validFormats := []string{"table", "json", "minimal"}
	if !contains(validFormats, m.config.Output.Format) {
		return fmt.Errorf("invalid output format: %s (must be one of: %v)", m.config.Output.Format, validFormats)
	}

	return nil
}

// contains checks if a string is in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// getConfigDir returns the config directory path
func getConfigDir() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		configDir = filepath.Join(home, ".config")
	}
	return filepath.Join(configDir, "secchain")
}
