package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// YARAScanner handles YARA rule matching inside sandbox
type YARAScanner struct {
	available   bool
	rulesPath   string
	customRules []string
}

// NewYARAScanner creates a new YARA scanner
func NewYARAScanner() *YARAScanner {
	return &YARAScanner{
		rulesPath: filepath.Join(getConfigDir(), "rules"),
	}
}

// Init initializes the YARA scanner
func (y *YARAScanner) Init() error {
	// Check if YARA is available (would check for yara binary or library)
	// For now, assume it's available if we can find the rules directory
	if _, err := os.Stat(y.rulesPath); os.IsNotExist(err) {
		// Create rules directory and default rules
		if err := os.MkdirAll(y.rulesPath, 0755); err != nil {
			y.available = false
			return fmt.Errorf("failed to create rules directory: %w", err)
		}
		
		// Create default rules
		if err := y.createDefaultRules(); err != nil {
			y.available = false
			return fmt.Errorf("failed to create default rules: %w", err)
		}
	}

	y.available = true
	return nil
}

// IsAvailable returns true if YARA is available
func (y *YARAScanner) IsAvailable() bool {
	return y.available
}

// ScanWithYARA scans package files with YARA rules
func (y *YARAScanner) ScanWithYARA(ctx context.Context, pkg, version, ecosystem string) ([]Finding, error) {
	if !y.available {
		return nil, fmt.Errorf("YARA not available")
	}

	var findings []Finding

	// This would run YARA inside the sandbox container
	// For now, return placeholder implementation
	
	// Scan for obfuscated code
	if finding := y.scanObfuscatedCode(pkg, version); finding != nil {
		findings = append(findings, *finding)
	}

	// Scan for suspicious eval/exec patterns
	if finding := y.scanSuspiciousPatterns(pkg, version); finding != nil {
		findings = append(findings, *finding)
	}

	// Scan for encoded network payloads
	if finding := y.scanEncodedPayloads(pkg, version); finding != nil {
		findings = append(findings, *finding)
	}

	// Scan for known malicious signatures
	if finding := y.scanMaliciousSignatures(pkg, version); finding != nil {
		findings = append(findings, *finding)
	}

	return findings, nil
}

// scanObfuscatedCode scans for obfuscated code patterns
func (y *YARAScanner) scanObfuscatedCode(pkg, version string) *Finding {
	// This would use YARA rules to detect base64 blobs, hex-encoded strings, etc.
	// For now, return placeholder
	return nil
}

// scanSuspiciousPatterns scans for suspicious eval/exec patterns
func (y *YARAScanner) scanSuspiciousPatterns(pkg, version string) *Finding {
	// This would use YARA rules to detect dangerous function calls
	// For now, return placeholder
	return nil
}

// scanEncodedPayloads scans for encoded network payloads
func (y *YARAScanner) scanEncodedPayloads(pkg, version string) *Finding {
	// This would use YARA rules to detect encoded URLs, IPs, etc.
	// For now, return placeholder
	return nil
}

// scanMaliciousSignatures scans for known malicious code signatures
func (y *YARAScanner) scanMaliciousSignatures(pkg, version string) *Finding {
	// This would use YARA rules to detect known attack patterns
	// For now, return placeholder
	return nil
}

// createDefaultRules creates the default YARA rules file
func (y *YARAScanner) createDefaultRules() error {
	rulesFile := filepath.Join(y.rulesPath, "default.yar")
	
	rules := `// DepSec Default YARA Rules
// These rules detect common malicious patterns in package code

rule Base64_Blob {
    meta:
        description = "Detects large base64 encoded blobs"
        severity = "medium"
    strings:
        $base64 = /[A-Za-z0-9+/]{100,}=*/ 
    condition:
        $base64 and #base64 > 10
}

rule Hex_Encoded_String {
    meta:
        description = "Detects hex encoded strings"
        severity = "medium"
    strings:
        $hex = /[0-9a-fA-F]{32,}/
    condition:
        $hex and #hex > 5
}

rule Suspicious_Eval {
    meta:
        description = "Detects suspicious eval usage"
        severity = "high"
    strings:
        $eval1 = "eval(" nocase
        $eval2 = "Function(" nocase
        $eval3 = "setTimeout(" nocase
        $eval4 = "setInterval(" nocase
    condition:
        any of them
}

rule Network_Call {
    meta:
        description = "Detects network function calls"
        severity = "medium"
    strings:
        $http1 = "http.get" nocase
        $http2 = "http.post" nocase
        $http3 = "fetch(" nocase
        $http4 = "XMLHttpRequest" nocase
        $http5 = "curl(" nocase
        $http6 = "wget(" nocase
    condition:
        any of them
}

rule File_System_Access {
    meta:
        description = "Detects file system access"
        severity = "medium"
    strings:
        $fs1 = "fs.readFile" nocase
        $fs2 = "fs.writeFile" nocase
        $fs3 = "open(" nocase
        $fs4 = "write(" nocase
        $fs5 = "exec(" nocase
    condition:
        any of them
}

rule Environment_Access {
    meta:
        description = "Detects environment variable access"
        severity = "high"
    strings:
        $env1 = "process.env" nocase
        $env2 = "os.environ" nocase
        $env3 = "getenv(" nocase
        $env4 = "$ENV{" nocase
    condition:
        any of them
}

rule Obfuscated_JavaScript {
    meta:
        description = "Detects heavily obfuscated JavaScript"
        severity = "high"
    strings:
        $obs1 = /\\[xu][0-9a-fA-F]{2,}/
        $obs2 = /\\\\[0-9]{3}/
        $obs3 = /\\%[0-9a-fA-F]{2}/
    condition:
        any of them and #obs1 > 10
}

rule Suspicious_Import {
    meta:
        description = "Detects suspicious module imports"
        severity = "medium"
    strings:
        $imp1 = "child_process" nocase
        $imp2 = "subprocess" nocase
        $imp3 = "os" nocase
        $imp4 = "fs" nocase
        $imp5 = "socket" nocase
    condition:
        any of them
}

rule Hardcoded_Secret {
    meta:
        description = "Detects potential hardcoded secrets"
        severity = "high"
    strings:
        $secret1 = /AIza[0-9A-Za-z_-]{35}/  // Google API key
        $secret2 = /sk-[a-zA-Z0-9]{20,}/      // Stripe key
        $secret3 = /ghp_[a-zA-Z0-9]{36}/      // GitHub token
        $secret4 = /xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}/ // Slack bot token
    condition:
        any of them
}
`

	return os.WriteFile(rulesFile, []byte(rules), 0644)
}

// AddCustomRule adds a custom YARA rule
func (y *YARAScanner) AddCustomRule(rulePath string) error {
	if _, err := os.Stat(rulePath); os.IsNotExist(err) {
		return fmt.Errorf("rule file does not exist: %s", rulePath)
	}
	
	y.customRules = append(y.customRules, rulePath)
	return nil
}

// UpdateRules updates YARA rules from remote source
func (y *YARAScanner) UpdateRules() error {
	// This would download updated rules from a remote source
	// For now, just recreate default rules
	return y.createDefaultRules()
}

// Helper function to get config directory
func getConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "depsec")
}
