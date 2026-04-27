package output

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/YsfDev1/SecChain/scanner"
)

// SARIFVersion is the SARIF specification version
const SARIFVersion = "2.1.0"

// SARIFSchemaURI is the JSON schema URI
const SARIFSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

// SARIFDocument represents the root SARIF document
type SARIFDocument struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run of a tool
type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
}

// SARIFTool represents the tool information
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver represents the tool driver
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule represents a rule that was violated
type SARIFRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name,omitempty"`
	ShortDescription     SARIFMessage           `json:"shortDescription,omitempty"`
	FullDescription      SARIFMessage           `json:"fullDescription,omitempty"`
	DefaultConfiguration SARIFConfiguration     `json:"defaultConfiguration,omitempty"`
	Properties           map[string]interface{} `json:"properties,omitempty"`
}

// SARIFMessage represents a text message
type SARIFMessage struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

// SARIFConfiguration represents rule configuration
type SARIFConfiguration struct {
	Level string `json:"level,omitempty"`
}

// SARIFResult represents a single finding
type SARIFResult struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    SARIFMessage           `json:"message"`
	Locations  []SARIFLocation        `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFLocation represents where a finding was found
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
}

// SARIFPhysicalLocation represents the physical location
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation represents the artifact location
type SARIFArtifactLocation struct {
	URI string `json:"uri,omitempty"`
}

// SARIFRegion represents a specific region in the artifact
type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// SARIFInvocation represents tool invocation details
type SARIFInvocation struct {
	ExecutionSuccessful bool      `json:"executionSuccessful"`
	StartTimeUTC        time.Time `json:"startTimeUtc,omitempty"`
	EndTimeUTC          time.Time `json:"endTimeUtc,omitempty"`
}

// SARIFFormatter generates SARIF output
type SARIFFormatter struct {
	toolVersion string
}

// NewSARIFFormatter creates a new SARIF formatter
func NewSARIFFormatter(version string) *SARIFFormatter {
	return &SARIFFormatter{
		toolVersion: version,
	}
}

// Format converts scan results to SARIF format
func (f *SARIFFormatter) Format(results []*scanner.ScanResult) (string, error) {
	doc := f.buildSARIFDocument(results)

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SARIF: %w", err)
	}

	return string(data), nil
}

// buildSARIFDocument builds the complete SARIF document
func (f *SARIFFormatter) buildSARIFDocument(results []*scanner.ScanResult) SARIFDocument {
	run := f.buildSARIFRun(results)

	return SARIFDocument{
		Version: SARIFVersion,
		Schema:  SARIFSchemaURI,
		Runs:    []SARIFRun{run},
	}
}

// buildSARIFRun builds a SARIF run from scan results
func (f *SARIFFormatter) buildSARIFRun(results []*scanner.ScanResult) SARIFRun {
	rules := make(map[string]SARIFRule)
	var sarifResults []SARIFResult

	for _, result := range results {
		for _, finding := range result.Findings {
			ruleID := f.generateRuleID(result.Package, finding)

			// Add rule if not exists
			if _, exists := rules[ruleID]; !exists {
				rules[ruleID] = f.buildSARIFRule(ruleID, finding)
			}

			// Add result
			sarifResult := f.buildSARIFResult(result, finding, ruleID)
			sarifResults = append(sarifResults, sarifResult)
		}
	}

	// Convert rules map to slice
	ruleSlice := make([]SARIFRule, 0, len(rules))
	for _, rule := range rules {
		ruleSlice = append(ruleSlice, rule)
	}

	return SARIFRun{
		Tool: SARIFTool{
			Driver: SARIFDriver{
				Name:           "SecChain",
				Version:        f.toolVersion,
				InformationURI: "https://github.com/YsfDev1/SecChain",
				Rules:          ruleSlice,
			},
		},
		Results: sarifResults,
		Invocations: []SARIFInvocation{
			{
				ExecutionSuccessful: true,
				StartTimeUTC:        time.Now().UTC(),
				EndTimeUTC:          time.Now().UTC(),
			},
		},
	}
}

// buildSARIFRule creates a SARIF rule from a finding
func (f *SARIFFormatter) buildSARIFRule(ruleID string, finding scanner.Finding) SARIFRule {
	return SARIFRule{
		ID:   ruleID,
		Name: finding.Layer + "-" + finding.Severity,
		ShortDescription: SARIFMessage{
			Text: finding.Reason,
		},
		FullDescription: SARIFMessage{
			Text: finding.Details,
		},
		DefaultConfiguration: SARIFConfiguration{
			Level: f.severityToSARIFLevel(finding.Severity),
		},
		Properties: map[string]interface{}{
			"layer":    finding.Layer,
			"severity": finding.Severity,
		},
	}
}

// buildSARIFResult creates a SARIF result from a finding
func (f *SARIFFormatter) buildSARIFResult(result *scanner.ScanResult, finding scanner.Finding, ruleID string) SARIFResult {
	return SARIFResult{
		RuleID: ruleID,
		Level:  f.severityToSARIFLevel(finding.Severity),
		Message: SARIFMessage{
			Text: finding.Reason,
		},
		Locations: []SARIFLocation{
			{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: fmt.Sprintf("%s@%s (%s)", result.Package, result.Version, result.Ecosystem),
					},
				},
			},
		},
		Properties: map[string]interface{}{
			"package":   result.Package,
			"version":   result.Version,
			"ecosystem": result.Ecosystem,
			"layer":     finding.Layer,
			"details":   finding.Details,
		},
	}
}

// generateRuleID creates a unique rule ID for a finding
func (f *SARIFFormatter) generateRuleID(pkg string, finding scanner.Finding) string {
	// Try to extract CVE/GHSA ID from reason if present
	if isCVEID(finding.Reason) {
		return extractCVEID(finding.Reason)
	}

	return fmt.Sprintf("SECCHAIN-%s-%s-%s", finding.Layer, finding.Severity, pkg)
}

// severityToSARIFLevel maps SecChain severity to SARIF level
func (f *SARIFFormatter) severityToSARIFLevel(severity string) string {
	switch severity {
	case "CRITICAL":
		return "error"
	case "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW":
		return "note"
	default:
		return "none"
	}
}

// isCVEID checks if text contains a CVE or GHSA identifier
func isCVEID(text string) bool {
	// Simple check - in production would use regex
	return len(text) > 4 && (text[:4] == "CVE-" || text[:5] == "GHSA-")
}

// extractCVEID extracts CVE/GHSA ID from text
func extractCVEID(text string) string {
	// Simple extraction - in production would use proper parsing
	if len(text) >= 4 && text[:4] == "CVE-" {
		return text[:13] // CVE-YYYY-NNNN
	}
	if len(text) >= 5 && text[:5] == "GHSA-" {
		return text[:9] // GHSA-XXXX
	}
	return ""
}

// WriteSARIFFile writes SARIF output to a file
func WriteSARIFFile(results []*scanner.ScanResult, filename string, version string) error {
	formatter := NewSARIFFormatter(version)
	output, err := formatter.Format(results)
	if err != nil {
		return err
	}

	return writeFile(filename, output)
}

// writeFile is a helper to write content to a file
func writeFile(filename, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}
