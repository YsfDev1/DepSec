package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/YsfDev1/SecChain/output"
	"github.com/YsfDev1/SecChain/scanner"
	"github.com/spf13/cobra"
)

var (
	scanPkg       string
	scanVersion   string
	scanEcosystem string
	scanFormat    string
	scanOffline   bool
	scanStrict    bool
	scanLogOnly   bool
)

var ScanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a local project directory or package",
	Long: `Scan a local project directory or package before installing.
Supports multiple ecosystems: node, python, rust, go, ruby`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		// Initialize scanning pipeline
		pipeline := scanner.NewPipeline()

		var results []*scanner.ScanResult
		var err error

		if scanPkg != "" {
			// Scan specific package
			if scanVersion == "" {
				// Try to get latest version (for now use "latest")
				scanVersion = "latest"
			}

			if scanEcosystem == "" {
				fmt.Fprintf(os.Stderr, "Error: --ecosystem is required when scanning a package\n")
				os.Exit(1)
			}

			fmt.Printf("Scanning package %s@%s (%s)...\n", scanPkg, scanVersion, scanEcosystem)
			result, err := pipeline.ScanPackage(ctx, scanPkg, scanVersion, scanEcosystem)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error scanning package: %v\n", err)
				os.Exit(1)
			}
			results = []*scanner.ScanResult{result}
		} else if len(args) > 0 {
			// Scan project directory
			projectPath := args[0]
			if !filepath.IsAbs(projectPath) {
				cwd, _ := os.Getwd()
				projectPath = filepath.Join(cwd, projectPath)
			}

			fmt.Printf("Scanning project directory: %s\n", projectPath)
			results, err = pipeline.ScanProject(ctx, projectPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error scanning project: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Error: Either specify a package with --pkg or provide a project path\n")
			os.Exit(1)
		}

		// Format and display results
		formatter := output.NewFormatter(scanFormat, true, false)
		output, err := formatter.Format(results)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting results: %v\n", err)
			os.Exit(1)
		}

		fmt.Print(output)

		// Check for risky packages
		hasRisks := false
		for _, result := range results {
			if !result.Clean {
				hasRisks = true
				break
			}
		}

		if hasRisks {
			if scanStrict {
				fmt.Printf("\n❌ Risks detected and strict mode enabled - aborting\n")
				os.Exit(1)
			} else if !scanLogOnly {
				fmt.Printf("\n⚠️  Risks detected - review results above\n")
			}
		} else {
			fmt.Printf("\n✅ All packages passed security scan\n")
		}
	},
}

func init() {
	ScanCmd.Flags().StringVar(&scanPkg, "pkg", "", "Package name to scan")
	ScanCmd.Flags().StringVar(&scanVersion, "version", "", "Package version (default: latest)")
	ScanCmd.Flags().StringVar(&scanEcosystem, "ecosystem", "", "Force ecosystem (node|python|rust|go|ruby)")
	ScanCmd.Flags().StringVar(&scanFormat, "format", "table", "Output format (table|json|minimal)")
	ScanCmd.Flags().BoolVar(&scanOffline, "offline", false, "Use cached data only")
	ScanCmd.Flags().BoolVar(&scanStrict, "strict", false, "Strict mode - fail on any risk")
	ScanCmd.Flags().BoolVar(&scanLogOnly, "log-only", false, "Log-only mode - never block")
}
