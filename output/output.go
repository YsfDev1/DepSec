package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/DepSec/scanner"
)

// Formatter handles different output formats for scan results
type Formatter struct {
	format    string
	showClean bool
	verbose   bool
}

// NewFormatter creates a new output formatter
func NewFormatter(format string, showClean, verbose bool) *Formatter {
	return &Formatter{
		format:    format,
		showClean: showClean,
		verbose:   verbose,
	}
}

// Format formats scan results according to the configured format
func (f *Formatter) Format(results []*scanner.ScanResult) (string, error) {
	switch f.format {
	case "table":
		return f.formatTable(results)
	case "json":
		return f.formatJSON(results)
	case "minimal":
		return f.formatMinimal(results)
	default:
		return "", fmt.Errorf("unsupported output format: %s", f.format)
	}
}

// formatTable formats results as a table
func (f *Formatter) formatTable(results []*scanner.ScanResult) (string, error) {
	var builder strings.Builder
	w := tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)

	// Header
	fmt.Fprintln(w, "PACKAGE\tVERSION\tECOSYSTEM\tSEVERITY\tLAYER\tREASON")

	for _, result := range results {
		// Skip clean results if showClean is false
		if result.Clean && !f.showClean {
			continue
		}

		if result.Clean {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				result.Package, result.Version, result.Ecosystem, "CLEAN", "—", "—")
		} else {
			// Show each finding
			for _, finding := range result.Findings {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					result.Package, result.Version, result.Ecosystem,
					finding.Severity, finding.Layer, f.truncateReason(finding.Reason))
			}
		}
	}

	w.Flush()
	return builder.String(), nil
}

// formatJSON formats results as JSON
func (f *Formatter) formatJSON(results []*scanner.ScanResult) (string, error) {
	var filteredResults []*scanner.ScanResult

	for _, result := range results {
		// Skip clean results if showClean is false
		if result.Clean && !f.showClean {
			continue
		}
		filteredResults = append(filteredResults, result)
	}

	data, err := json.MarshalIndent(filteredResults, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return string(data), nil
}

// formatMinimal formats results in a minimal way suitable for scripts
func (f *Formatter) formatMinimal(results []*scanner.ScanResult) (string, error) {
	var builder strings.Builder

	for _, result := range results {
		// Skip clean results if showClean is false
		if result.Clean && !f.showClean {
			continue
		}

		if result.Clean {
			fmt.Fprintf(&builder, "%s@%s: CLEAN\n", result.Package, result.Version)
		} else {
			// Show only package name and highest severity
			highestSeverity := f.getHighestSeverity(result.Findings)
			fmt.Fprintf(&builder, "%s@%s: %s\n", result.Package, result.Version, highestSeverity)
		}
	}

	return builder.String(), nil
}

// FormatRisk formats a single risk finding for interactive mode
func (f *Formatter) FormatRisk(result *scanner.ScanResult, finding *scanner.Finding) string {
	var builder strings.Builder

	fmt.Fprintf(&builder, "⚠️  RISK DETECTED: %s@%s\n", result.Package, result.Version)
	fmt.Fprintf(&builder, "    Layer: %s — %s\n", finding.Layer, finding.Reason)
	fmt.Fprintf(&builder, "    Severity: %s\n", finding.Severity)

	if f.verbose {
		fmt.Fprintf(&builder, "    Details: %s\n", finding.Details)
	}

	fmt.Fprintf(&builder, "\n    [Y] Install anyway   [N] Cancel   [D] Show full details\n")

	return builder.String()
}

// FormatStatus formats system status information
func (f *Formatter) FormatStatus(status map[string]interface{}) string {
	var builder strings.Builder

	fmt.Fprintf(&builder, "DepSec Status:\n")
	fmt.Fprintf(&builder, "  Mode: %s\n", status["mode"])
	fmt.Fprintf(&builder, "  Min Severity: %s\n", status["min_severity"])
	fmt.Fprintf(&builder, "  Offline: %t\n", status["offline"])
	
	if autoScan, ok := status["auto_scan"].(map[string]interface{}); ok {
		fmt.Fprintf(&builder, "  Auto-Scan: %t\n", autoScan["enabled"])
		if ecosystems, ok := autoScan["ecosystems"].([]string); ok {
			fmt.Fprintf(&builder, "    Ecosystems: %s\n", strings.Join(ecosystems, ", "))
		}
	}
	
	if docker, ok := status["docker"].(map[string]interface{}); ok {
		fmt.Fprintf(&builder, "  Docker: %t\n", docker["enabled"])
	}
	
	if clamav, ok := status["clamav"].(map[string]interface{}); ok {
		fmt.Fprintf(&builder, "  ClamAV: %t\n", clamav["enabled"])
	}
	
	if yara, ok := status["yara"].(map[string]interface{}); ok {
		fmt.Fprintf(&builder, "  YARA: %t\n", yara["enabled"])
	}

	return builder.String()
}

// FormatDoctor formats health check results
func (f *Formatter) FormatDoctor(checks []HealthCheck) string {
	var builder strings.Builder

	fmt.Fprintf(&builder, "DepSec Health Check:\n\n")

	for _, check := range checks {
		status := "✅"
		if !check.Passed {
			status = "❌"
		}
		
		fmt.Fprintf(&builder, "%s %s\n", status, check.Name)
		if check.Message != "" {
			fmt.Fprintf(&builder, "   %s\n", check.Message)
		}
		if !check.Passed && check.Suggestion != "" {
			fmt.Fprintf(&builder, "   💡 %s\n", check.Suggestion)
		}
		fmt.Fprintf(&builder, "\n")
	}

	return builder.String()
}

// truncateReason truncates reason for table display
func (f *Formatter) truncateReason(reason string) string {
	maxLength := 50
	if len(reason) <= maxLength {
		return reason
	}
	return reason[:maxLength-3] + "..."
}

// getHighestSeverity returns the highest severity from findings
func (f *Formatter) getHighestSeverity(findings []scanner.Finding) string {
	if len(findings) == 0 {
		return "CLEAN"
	}

	severityOrder := map[string]int{
		"LOW":      1,
		"MEDIUM":    2,
		"HIGH":     3,
		"CRITICAL": 4,
	}

	highest := findings[0].Severity
	highestLevel := severityOrder[highest]

	for _, finding := range findings {
		if level, exists := severityOrder[finding.Severity]; exists && level > highestLevel {
			highest = finding.Severity
			highestLevel = level
		}
	}

	return highest
}

// HealthCheck represents a health check result
type HealthCheck struct {
	Name        string
	Passed      bool
	Message     string
	Suggestion  string
}

// ScanSummary represents a summary of scan results
type ScanSummary struct {
	Total      int
	Clean      int
	Low        int
	Medium     int
	High       int
	Critical   int
	Duration   string
}

// FormatSummary formats a scan summary
func (f *Formatter) FormatSummary(summary ScanSummary) string {
	var builder strings.Builder

	fmt.Fprintf(&builder, "Scan Summary:\n")
	fmt.Fprintf(&builder, "  Total packages: %d\n", summary.Total)
	fmt.Fprintf(&builder, "  Clean: %d\n", summary.Clean)
	fmt.Fprintf(&builder, "  Low severity: %d\n", summary.Low)
	fmt.Fprintf(&builder, "  Medium severity: %d\n", summary.Medium)
	fmt.Fprintf(&builder, "  High severity: %d\n", summary.High)
	fmt.Fprintf(&builder, "  Critical severity: %d\n", summary.Critical)
	fmt.Fprintf(&builder, "  Duration: %s\n", summary.Duration)

	return builder.String()
}
