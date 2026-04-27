package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/YsfDev1/SecChain/scanner"
)

// BaselineFile is the default name for the baseline file
const BaselineFile = ".secchainbaseline"

// IgnoreFile is the default name for the ignore file
const IgnoreFile = ".secchainignore"

// Baseline represents a scan baseline for comparison
type Baseline struct {
	CreatedAt   time.Time       `json:"created_at"`
	SecChainVersion string      `json:"secchain_version"`
	Packages    []BaselinePackage `json:"packages"`
}

// BaselinePackage represents a package in the baseline
type BaselinePackage struct {
	Name      string           `json:"name"`
	Version   string           `json:"version"`
	Ecosystem string           `json:"ecosystem"`
	Findings  []BaselineFinding `json:"findings"`
}

// BaselineFinding represents a finding in the baseline
type BaselineFinding struct {
	Layer    string `json:"layer"`
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
	RuleID   string `json:"rule_id,omitempty"`
}

// IgnoreRule represents a rule for ignoring findings
type IgnoreRule struct {
	Package   string    `json:"package,omitempty"`
	Version   string    `json:"version,omitempty"`
	Ecosystem string    `json:"ecosystem,omitempty"`
	RuleID    string    `json:"rule_id,omitempty"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// IgnoreList represents a list of ignore rules
type IgnoreList struct {
	Version string       `json:"version"`
	Rules   []IgnoreRule `json:"rules"`
}

// BaselineManager handles baseline operations
type BaselineManager struct {
	projectPath string
}

// NewBaselineManager creates a new baseline manager
func NewBaselineManager(projectPath string) *BaselineManager {
	return &BaselineManager{
		projectPath: projectPath,
	}
}

// CreateBaseline creates a baseline from scan results
func (bm *BaselineManager) CreateBaseline(results []*scanner.ScanResult, version string) *Baseline {
	baseline := &Baseline{
		CreatedAt:       time.Now(),
		SecChainVersion: version,
		Packages:        make([]BaselinePackage, 0, len(results)),
	}

	for _, result := range results {
		pkg := BaselinePackage{
			Name:      result.Package,
			Version:   result.Version,
			Ecosystem: result.Ecosystem,
			Findings:  make([]BaselineFinding, 0, len(result.Findings)),
		}

		for _, finding := range result.Findings {
			pkg.Findings = append(pkg.Findings, BaselineFinding{
				Layer:    finding.Layer,
				Severity: finding.Severity,
				Reason:   finding.Reason,
			})
		}

		baseline.Packages = append(baseline.Packages, pkg)
	}

	return baseline
}

// SaveBaseline saves the baseline to a file
func (bm *BaselineManager) SaveBaseline(baseline *Baseline) error {
	baselinePath := filepath.Join(bm.projectPath, BaselineFile)

	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	if err := os.WriteFile(baselinePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write baseline file: %w", err)
	}

	return nil
}

// LoadBaseline loads a baseline from a file
func (bm *BaselineManager) LoadBaseline() (*Baseline, error) {
	baselinePath := filepath.Join(bm.projectPath, BaselineFile)

	data, err := os.ReadFile(baselinePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read baseline file: %w", err)
	}

	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("failed to parse baseline file: %w", err)
	}

	return &baseline, nil
}

// LoadIgnoreList loads the ignore list from a file
func (bm *BaselineManager) LoadIgnoreList() (*IgnoreList, error) {
	ignorePath := filepath.Join(bm.projectPath, IgnoreFile)

	data, err := os.ReadFile(ignorePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read ignore file: %w", err)
	}

	var ignoreList IgnoreList
	if err := json.Unmarshal(data, &ignoreList); err != nil {
		return nil, fmt.Errorf("failed to parse ignore file: %w", err)
	}

	return &ignoreList, nil
}

// FilterWithBaseline filters results to only show new findings compared to baseline
func (bm *BaselineManager) FilterWithBaseline(results []*scanner.ScanResult, baseline *Baseline) []*scanner.ScanResult {
	if baseline == nil {
		return results
	}

	// Build map of existing findings
	existingFindings := make(map[string]bool)
	for _, pkg := range baseline.Packages {
		for _, finding := range pkg.Findings {
			key := fmt.Sprintf("%s@%s:%s:%s:%s", pkg.Name, pkg.Version, pkg.Ecosystem, finding.Layer, finding.Reason)
			existingFindings[key] = true
		}
	}

	// Filter results
	var filtered []*scanner.ScanResult
	for _, result := range results {
		var newFindings []scanner.Finding
		for _, finding := range result.Findings {
			key := fmt.Sprintf("%s@%s:%s:%s:%s", result.Package, result.Version, result.Ecosystem, finding.Layer, finding.Reason)
			if !existingFindings[key] {
				newFindings = append(newFindings, finding)
			}
		}

		if len(newFindings) > 0 {
			filtered = append(filtered, &scanner.ScanResult{
				Package:   result.Package,
				Version:   result.Version,
				Ecosystem: result.Ecosystem,
				Findings:  newFindings,
				Clean:     false,
			})
		}
	}

	return filtered
}

// FilterWithIgnoreList filters results based on ignore rules
func (bm *BaselineManager) FilterWithIgnoreList(results []*scanner.ScanResult, ignoreList *IgnoreList) []*scanner.ScanResult {
	if ignoreList == nil || len(ignoreList.Rules) == 0 {
		return results
	}

	now := time.Now()
	var filtered []*scanner.ScanResult

	for _, result := range results {
		var newFindings []scanner.Finding
		for _, finding := range result.Findings {
			if !bm.shouldIgnore(result, finding, ignoreList, now) {
				newFindings = append(newFindings, finding)
			}
		}

		if len(newFindings) > 0 {
			filtered = append(filtered, &scanner.ScanResult{
				Package:   result.Package,
				Version:   result.Version,
				Ecosystem: result.Ecosystem,
				Findings:  newFindings,
				Clean:     false,
			})
		}
	}

	return filtered
}

// shouldIgnore checks if a finding should be ignored based on rules
func (bm *BaselineManager) shouldIgnore(result *scanner.ScanResult, finding scanner.Finding, ignoreList *IgnoreList, now time.Time) bool {
	for _, rule := range ignoreList.Rules {
		// Check if rule has expired
		if !rule.ExpiresAt.IsZero() && now.After(rule.ExpiresAt) {
			continue
		}

		// Check package match
		if rule.Package != "" && !bm.matches(rule.Package, result.Package) {
			continue
		}

		// Check version match
		if rule.Version != "" && rule.Version != result.Version {
			continue
		}

		// Check ecosystem match
		if rule.Ecosystem != "" && rule.Ecosystem != result.Ecosystem {
			continue
		}

		// Check rule ID match
		if rule.RuleID != "" && !bm.matchesRuleID(rule.RuleID, finding) {
			continue
		}

		// All criteria match - ignore this finding
		return true
	}

	return false
}

// matches checks if a pattern matches a value (supports wildcards)
func (bm *BaselineManager) matches(pattern, value string) bool {
	if pattern == "*" || pattern == value {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(value, prefix)
	}
	return pattern == value
}

// matchesRuleID checks if a finding matches a rule ID
func (bm *BaselineManager) matchesRuleID(ruleID string, finding scanner.Finding) bool {
	// Check if rule ID is in the finding reason or details
	if strings.Contains(finding.Reason, ruleID) {
		return true
	}
	if strings.Contains(finding.Details, ruleID) {
		return true
	}
	return false
}

// GenerateIgnoreTemplate generates a template ignore file
func (bm *BaselineManager) GenerateIgnoreTemplate() string {
	template := &IgnoreList{
		Version: "1.0",
		Rules: []IgnoreRule{
			{
				Package:   "example-package",
				Version:   "1.0.0",
				Ecosystem: "node",
				RuleID:    "GHSA-xxxx-xxxx-xxxx",
				Reason:    "Internal use only, not exposed to user input",
				ExpiresAt: time.Now().AddDate(0, 3, 0),
			},
			{
				Package:   "legacy-*",
				Ecosystem: "python",
				Reason:    "Legacy dependencies scheduled for migration",
			},
		},
	}

	data, _ := json.MarshalIndent(template, "", "  ")
	return string(data)
}

// HasBaseline checks if a baseline file exists
func (bm *BaselineManager) HasBaseline() bool {
	baselinePath := filepath.Join(bm.projectPath, BaselineFile)
	_, err := os.Stat(baselinePath)
	return err == nil
}

// HasIgnoreFile checks if an ignore file exists
func (bm *BaselineManager) HasIgnoreFile() bool {
	ignorePath := filepath.Join(bm.projectPath, IgnoreFile)
	_, err := os.Stat(ignorePath)
	return err == nil
}
