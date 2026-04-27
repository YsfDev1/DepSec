package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/YsfDev1/SecChain/config"
	"github.com/YsfDev1/SecChain/output"
	"github.com/YsfDev1/SecChain/scanner"
	"github.com/spf13/cobra"
)

var (
	scanPkg         string
	scanVersion     string
	scanEcosystem   string
	scanFormat      string
	scanOffline     bool
	scanStrict      bool
	scanLogOnly     bool
	scanBaseline    string
	scanIgnore      string
	scanSarifOutput string
	scanExitCode    bool
)

var ScanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a local project directory or package",
	Long: `Scan a local project directory or package before installing.
Supports multiple ecosystems: node, python, rust, go, ruby`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		// Load config to get minSeverity
		configManager, cfgErr := config.NewManager()
		if cfgErr != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", cfgErr)
			os.Exit(ExitCodeError)
		}
		cfg := configManager.Get()
		minSeverity := cfg.MinSeverity

		// Initialize scanning pipeline
		pipeline := scanner.NewPipeline()

		var results []*scanner.ScanResult
		var err error
		var projectPath string

		if scanPkg != "" {
			// Scan specific package
			if scanVersion == "" {
				scanVersion = "latest"
			}

			if scanEcosystem == "" {
				fmt.Fprintf(os.Stderr, "Error: --ecosystem is required when scanning a package\n")
				os.Exit(ExitCodeError)
			}

			fmt.Printf("Scanning package %s@%s (%s)...\n", scanPkg, scanVersion, scanEcosystem)
			result, err := pipeline.ScanPackage(ctx, scanPkg, scanVersion, scanEcosystem, minSeverity)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error scanning package: %v\n", err)
				os.Exit(ExitCodeError)
			}
			results = []*scanner.ScanResult{result}
		} else if len(args) > 0 {
			// Scan project directory
			projectPath = args[0]
			if !filepath.IsAbs(projectPath) {
				cwd, _ := os.Getwd()
				projectPath = filepath.Join(cwd, projectPath)
			}

			fmt.Printf("Scanning project directory: %s\n", projectPath)
			results, err = pipeline.ScanProject(ctx, projectPath, minSeverity)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error scanning project: %v\n", err)
				os.Exit(ExitCodeError)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Error: Either specify a package with --pkg or provide a project path\n")
			os.Exit(ExitCodeError)
		}

		// Apply baseline filtering if requested
		if scanBaseline != "" || fileExists(filepath.Join(projectPath, config.BaselineFile)) {
			baselinePath := scanBaseline
			if baselinePath == "" {
				baselinePath = filepath.Join(projectPath, config.BaselineFile)
			}
			bm := config.NewBaselineManager(filepath.Dir(baselinePath))
			baseline, _ := bm.LoadBaseline()
			if baseline != nil {
				fmt.Printf("Applying baseline filter: %d packages in baseline\n", len(baseline.Packages))
				results = bm.FilterWithBaseline(results, baseline)
			}
		}

		// Apply ignore rules if requested
		if scanIgnore != "" || fileExists(filepath.Join(projectPath, config.IgnoreFile)) {
			ignorePath := scanIgnore
			if ignorePath == "" {
				ignorePath = filepath.Join(projectPath, config.IgnoreFile)
			}
			bm := config.NewBaselineManager(filepath.Dir(ignorePath))
			ignoreList, _ := bm.LoadIgnoreList()
			if ignoreList != nil {
				results = bm.FilterWithIgnoreList(results, ignoreList)
			}
		}

		// Generate SARIF output if requested
		if scanSarifOutput != "" || scanFormat == "sarif" {
			sarifFile := scanSarifOutput
			if sarifFile == "" {
				sarifFile = "secchain-results.sarif"
			}
			version := "0.1.5"
			if err := output.WriteSARIFFile(results, sarifFile, version); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing SARIF file: %v\n", err)
			} else {
				fmt.Printf("SARIF report written to: %s\n", sarifFile)
			}
		}

		// Format and display results (unless only SARIF output requested)
		if scanFormat != "sarif" || scanSarifOutput == "" {
			formatter := output.NewFormatter(scanFormat, true, false)
			out, err := formatter.Format(results)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error formatting results: %v\n", err)
				os.Exit(ExitCodeError)
			}
			fmt.Print(out)
		}

		// Calculate exit code and summary
		exitCode := calculateExitCode(results, scanStrict)

		// Print summary
		if exitCode == ExitCodeSuccess {
			fmt.Printf("\n✅ All packages passed security scan\n")
		} else if exitCode == ExitCodeCritical {
			fmt.Printf("\n❌ Critical vulnerabilities found - immediate action required\n")
		} else if scanStrict {
			fmt.Printf("\n❌ Risks detected and strict mode enabled - aborting\n")
		} else if !scanLogOnly {
			fmt.Printf("\n⚠️  Risks detected - review results above\n")
		}

		// Exit with appropriate code
		if scanExitCode {
			os.Exit(exitCode)
		}
	},
}

// Exit codes for CI/CD integration
const (
	ExitCodeSuccess  = 0 // No findings or all below threshold
	ExitCodeFindings = 1 // Findings detected
	ExitCodeError    = 2 // Tool error (network, config, etc.)
	ExitCodeCritical = 3 // Critical vulnerabilities found
)

// calculateExitCode determines the appropriate exit code based on scan results
func calculateExitCode(results []*scanner.ScanResult, strict bool) int {
	hasFindings := false
	hasCritical := false
	severityOrder := map[string]int{
		"LOW":      1,
		"MEDIUM":   2,
		"HIGH":     3,
		"CRITICAL": 4,
	}

	for _, result := range results {
		if !result.Clean {
			hasFindings = true
			for _, finding := range result.Findings {
				if level, ok := severityOrder[finding.Severity]; ok && level >= 4 {
					hasCritical = true
					break
				}
			}
		}
	}

	if hasCritical {
		return ExitCodeCritical
	}
	if hasFindings {
		return ExitCodeFindings
	}
	return ExitCodeSuccess
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func init() {
	ScanCmd.Flags().StringVar(&scanPkg, "pkg", "", "Package name to scan")
	ScanCmd.Flags().StringVar(&scanVersion, "version", "", "Package version (default: latest)")
	ScanCmd.Flags().StringVar(&scanEcosystem, "ecosystem", "", "Force ecosystem (node|python|rust|go|ruby)")
	ScanCmd.Flags().StringVar(&scanFormat, "format", "table", "Output format (table|json|minimal|sarif)")
	ScanCmd.Flags().BoolVar(&scanOffline, "offline", false, "Use cached data only")
	ScanCmd.Flags().BoolVar(&scanStrict, "strict", false, "Strict mode - fail on any risk")
	ScanCmd.Flags().BoolVar(&scanLogOnly, "log-only", false, "Log-only mode - never block")
	ScanCmd.Flags().StringVar(&scanBaseline, "baseline", "", "Path to baseline file for comparison")
	ScanCmd.Flags().StringVar(&scanIgnore, "ignore", "", "Path to ignore file with rules")
	ScanCmd.Flags().StringVar(&scanSarifOutput, "sarif-output", "", "Output file for SARIF format (CI integration)")
	ScanCmd.Flags().BoolVar(&scanExitCode, "exit-code", true, "Use standard exit codes (0=success, 1=findings, 2=error, 3=critical)")
}
