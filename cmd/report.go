package cmd

import (
	"fmt"
	"os"

	"github.com/YsfDev1/DepSec/cache"
	"github.com/YsfDev1/DepSec/output"
	"github.com/YsfDev1/DepSec/scanner"
	"github.com/spf13/cobra"
)

var (
	reportHistory bool
	reportPkg     string
	reportFormat  string
)

var ReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Show scan reports",
	Long:  `Display scan results and history`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize cache
		cacheManager, err := cache.NewCache()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing cache: %v\n", err)
			os.Exit(1)
		}
		defer cacheManager.Close()

		var results []*scanner.ScanResult

		if reportPkg != "" {
			// Show report for specific package
			result, err := cacheManager.GetScanResult(reportPkg, "latest", "")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting package report: %v\n", err)
				os.Exit(1)
			}
			if result == nil {
				fmt.Printf("No scan results found for package: %s\n", reportPkg)
				return
			}
			// Convert cached result to ScanResult (simplified)
			results = []*scanner.ScanResult{{}}
		} else if reportHistory {
			// Show all past scan results (placeholder - would need to implement history)
			fmt.Println("📜 Scan History:")
			fmt.Println("   (History feature not yet implemented)")
			return
		} else {
			// Show last scan report
			fmt.Println("📊 Last Scan Report:")
			fmt.Println("   (Last scan feature not yet implemented)")
			return
		}

		// Format and display results
		formatter := output.NewFormatter(reportFormat, true, false)
		output, err := formatter.Format(results)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting results: %v\n", err)
			os.Exit(1)
		}

		fmt.Print(output)
	},
}

func init() {
	ReportCmd.Flags().BoolVar(&reportHistory, "history", false, "Show all past scan results")
	ReportCmd.Flags().StringVar(&reportPkg, "pkg", "", "Show report for a specific package")
	ReportCmd.Flags().StringVar(&reportFormat, "format", "table", "Output format (table|json|minimal)")
}
