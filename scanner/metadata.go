package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// MetadataChecker handles metadata anomaly detection
type MetadataChecker struct {
	topPackages map[string][]string // ecosystem -> top packages list
}

// NewMetadataChecker creates a new metadata checker
func NewMetadataChecker() *MetadataChecker {
	return &MetadataChecker{
		topPackages: make(map[string][]string),
	}
}

// Init initializes the metadata checker with top packages data
func (m *MetadataChecker) Init() error {
	// Initialize top packages for each ecosystem
	m.topPackages = map[string][]string{
		"node":   m.getTopNodePackages(),
		"python": m.getTopPythonPackages(),
		"rust":   m.getTopRustPackages(),
		"go":     m.getTopGoPackages(),
		"ruby":   m.getTopRubyPackages(),
	}
	return nil
}

// CheckMetadata performs metadata anomaly detection on a package
func (m *MetadataChecker) CheckMetadata(ctx context.Context, pkg, version, ecosystem string) ([]Finding, error) {
	var findings []Finding

	// Check 1: Package publish date (flag if < 7 days old)
	if finding, err := m.checkPublishDate(ctx, pkg, version, ecosystem); err == nil && finding != nil {
		findings = append(findings, *finding)
	}

	// Check 2: Typosquatting detection
	if typosquatFinding := m.checkTyposquatting(pkg, ecosystem); typosquatFinding != nil {
		findings = append(findings, *typosquatFinding)
	}

	// Check 3: Suspicious install scripts
	if scriptFindings, err := m.checkInstallScripts(ctx, pkg, version, ecosystem); err == nil {
		findings = append(findings, scriptFindings...)
	}

	// Check 4: Maintainer change detection
	if maintainerFinding, err := m.checkMaintainerChanges(ctx, pkg, ecosystem); err == nil && maintainerFinding != nil {
		findings = append(findings, *maintainerFinding)
	}

	return findings, nil
}

// checkPublishDate checks if package was published less than 7 days ago
func (m *MetadataChecker) checkPublishDate(ctx context.Context, pkg, version, ecosystem string) (*Finding, error) {
	publishDate, err := m.getPackagePublishDate(ctx, pkg, version, ecosystem)
	if err != nil {
		return nil, err // Don't fail the scan if we can't get publish date
	}

	if time.Since(publishDate) < 7*24*time.Hour {
		return &Finding{
			Layer:    "Metadata",
			Severity: "MEDIUM",
			Reason:   fmt.Sprintf("Package %s@%s published less than 7 days ago (%s)", pkg, version, publishDate.Format("2006-01-02")),
			Details:  "Recently published packages may not have been thoroughly vetted by the community",
		}, nil
	}

	return nil, nil
}

// checkTyposquatting detects potential typosquatting attacks
func (m *MetadataChecker) checkTyposquatting(pkg, ecosystem string) *Finding {
	topPackages, exists := m.topPackages[ecosystem]
	if !exists {
		return nil
	}

	for _, topPkg := range topPackages {
		if m.isTyposquat(pkg, topPkg) {
			return &Finding{
				Layer:    "Metadata",
				Severity: "HIGH",
				Reason:   fmt.Sprintf("Potential typosquatting: %s is similar to popular package %s", pkg, topPkg),
				Details:  "Typosquatting packages mimic popular package names to trick users into installing malicious code",
			}
		}
	}

	return nil
}

// checkInstallScripts checks for suspicious install scripts
func (m *MetadataChecker) checkInstallScripts(ctx context.Context, pkg, version, ecosystem string) ([]Finding, error) {
	scripts, err := m.getInstallScripts(ctx, pkg, version, ecosystem)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	suspiciousCommands := []string{"curl", "wget", "fetch", "exec", "eval"}

	for scriptType, scriptContent := range scripts {
		for _, cmd := range suspiciousCommands {
			if strings.Contains(strings.ToLower(scriptContent), cmd) {
				findings = append(findings, Finding{
					Layer:    "Metadata",
					Severity: "HIGH",
					Reason:   fmt.Sprintf("Suspicious %s script contains command: %s", scriptType, cmd),
					Details:  fmt.Sprintf("Package %s@%s has potentially dangerous install script", pkg, version),
				})
			}
		}
	}

	return findings, nil
}

// checkMaintainerChanges checks for maintainer changes
func (m *MetadataChecker) checkMaintainerChanges(ctx context.Context, pkg, ecosystem string) (*Finding, error) {
	// This would require historical data from package registries
	// For now, return nil as a placeholder
	return nil, nil
}

// isTyposquat checks if a package name is a potential typosquat of another
func (m *MetadataChecker) isTyposquat(pkg, popular string) bool {
	// Skip if names are identical
	if pkg == popular {
		return false
	}

	// Check for common typosquatting patterns
	// 1. Single character substitution/insertion/deletion
	if m.isLevenshteinClose(pkg, popular, 1) {
		return true
	}

	// 2. Character transposition
	if m.isTransposition(pkg, popular) {
		return true
	}

	// 3. Common character confusion (e.g., l vs 1, o vs 0)
	if m.hasCharacterConfusion(pkg, popular) {
		return true
	}

	return false
}

// isLevenshteinClose checks if strings are within edit distance
func (m *MetadataChecker) isLevenshteinClose(s1, s2 string, maxDistance int) bool {
	// Simple implementation - in production would use proper Levenshtein algorithm
	if len(s1) != len(s2) && len(s1) != len(s2)+1 && len(s1)+1 != len(s2) {
		return false
	}

	distance := 0
	i, j := 0, 0
	for i < len(s1) && j < len(s2) {
		if s1[i] != s2[j] {
			distance++
			if distance > maxDistance {
				return false
			}
			// Skip character in longer string
			if len(s1) > len(s2) {
				i++
			} else if len(s2) > len(s1) {
				j++
			} else {
				i++
				j++
			}
		} else {
			i++
			j++
		}
	}

	return distance <= maxDistance
}

// isTransposition checks if strings differ by character transposition
func (m *MetadataChecker) isTransposition(s1, s2 string) bool {
	if len(s1) != len(s2) {
		return false
	}

	// Find first differing character
	for i := 0; i < len(s1)-1; i++ {
		if s1[i] != s2[i] {
			// Check if transposition of next character fixes it
			if s1[i] == s2[i+1] && s1[i+1] == s2[i] {
				// Check if rest of string matches
				return s1[i+2:] == s2[i+2:]
			}
			return false
		}
	}

	return false
}

// hasCharacterConfusion checks for visually similar character substitution
func (m *MetadataChecker) hasCharacterConfusion(s1, s2 string) bool {
	confusionMap := map[rune][]rune{
		'l': {'1'},
		'o': {'0'},
		'i': {'1'},
		's': {'5'},
		'g': {'9'},
	}

	if len(s1) != len(s2) {
		return false
	}

	for i, char1 := range s1 {
		char2 := rune(s2[i])
		if char1 != char2 {
			// Check if this is a known character confusion
			if confused, exists := confusionMap[char1]; exists {
				for _, confusedChar := range confused {
					if confusedChar == char2 {
						return true
					}
				}
			}
			return false
		}
	}

	return false
}

// getPackagePublishDate gets the publish date from package registry
func (m *MetadataChecker) getPackagePublishDate(ctx context.Context, pkg, version, ecosystem string) (time.Time, error) {
	switch ecosystem {
	case "node":
		return m.getNodePublishDate(ctx, pkg, version)
	case "python":
		return m.getPythonPublishDate(ctx, pkg, version)
	default:
		return time.Time{}, fmt.Errorf("unsupported ecosystem: %s", ecosystem)
	}
}

// getNodePublishDate gets publish date from npm registry
func (m *MetadataChecker) getNodePublishDate(ctx context.Context, pkg, version string) (time.Time, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s/%s", pkg, version)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("User-Agent", "DepSec/0.1.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("npm API returned status %d", resp.StatusCode)
	}

	var packageInfo struct {
		Time struct {
			Created string `json:"created"`
			Modified string `json:"modified"`
			Version string `json:"version"`
		} `json:"time"`
		Version string `json:"version"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&packageInfo); err != nil {
		return time.Time{}, err
	}

	// Use the version-specific publish time if available, otherwise use created time
	publishTime := packageInfo.Time.Created
	if packageInfo.Time.Version != "" {
		publishTime = packageInfo.Time.Version
	}

	return time.Parse(time.RFC3339, publishTime)
}

// getPythonPublishDate gets publish date from PyPI
func (m *MetadataChecker) getPythonPublishDate(ctx context.Context, pkg, version string) (time.Time, error) {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", pkg, version)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("User-Agent", "DepSec/0.1.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("PyPI API returned status %d", resp.StatusCode)
	}

	var packageInfo struct {
		UploadTime string `json:"upload_time"`
		Releases map[string][]struct {
			UploadTime string `json:"upload_time"`
		} `json:"releases"`
		Urls []struct {
			UploadTime string `json:"upload_time"`
		} `json:"urls"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&packageInfo); err != nil {
		return time.Time{}, err
	}

	// Try to get version-specific upload time
	if releases, ok := packageInfo.Releases[version]; ok && len(releases) > 0 {
		if releases[0].UploadTime != "" {
			return time.Parse(time.RFC3339, releases[0].UploadTime)
		}
	}

	// Fallback to general upload time
	if packageInfo.UploadTime != "" {
		return time.Parse(time.RFC3339, packageInfo.UploadTime)
	}

	return time.Time{}, fmt.Errorf("no upload time found for %s@%s", pkg, version)
}

// getInstallScripts gets install scripts from package metadata
func (m *MetadataChecker) getInstallScripts(ctx context.Context, pkg, version, ecosystem string) (map[string]string, error) {
	switch ecosystem {
	case "node":
		return m.getNodeInstallScripts(ctx, pkg, version)
	default:
		return map[string]string{}, nil
	}
}

// getNodeInstallScripts gets install scripts from npm package
func (m *MetadataChecker) getNodeInstallScripts(ctx context.Context, pkg, version string) (map[string]string, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s/%s", pkg, version)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "DepSec/0.1.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm API returned status %d", resp.StatusCode)
	}

	var packageInfo struct {
		Scripts map[string]string `json:"scripts"`
		Maintainers []struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"maintainers"`
		Author struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"author"`
		Repository struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"repository"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&packageInfo); err != nil {
		return nil, err
	}

	suspiciousScripts := map[string]string{}
	suspiciousKeys := []string{"preinstall", "postinstall", "install", "prepublish", "prepack", "postpack", "prestart", "poststart"}

	for _, key := range suspiciousKeys {
		if script, exists := packageInfo.Scripts[key]; exists {
			suspiciousScripts[key] = script
		}
	}

	return suspiciousScripts, nil
}

// Top packages lists (simplified - would be loaded from external source)
func (m *MetadataChecker) getTopNodePackages() []string {
	return []string{"lodash", "react", "angular", "vue", "express", "moment", "axios", "webpack", "babel", "typescript"}
}

func (m *MetadataChecker) getTopPythonPackages() []string {
	return []string{"requests", "numpy", "pandas", "flask", "django", "tensorflow", "pytorch", "scipy", "matplotlib", "pillow"}
}

func (m *MetadataChecker) getTopRustPackages() []string {
	return []string{"serde", "tokio", "rayon", "regex", "log", "clap", "serde_json", "anyhow", "thiserror", "tracing"}
}

func (m *MetadataChecker) getTopGoPackages() []string {
	return []string{"github.com/gin-gonic/gin", "github.com/gorilla/mux", "github.com/stretchr/testify", "github.com/spf13/cobra", "github.com/spf13/viper"}
}

func (m *MetadataChecker) getTopRubyPackages() []string {
	return []string{"rails", "devise", "puma", "rspec", "sidekiq", "factory_bot", "simple_form", "pg", "redis", "dotenv"}
}
