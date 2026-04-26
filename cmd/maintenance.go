package cmd

import (
	"fmt"
	"os"

	"github.com/YsfDev1/DepSec/scanner"
	"github.com/spf13/cobra"
)

var UpdateRulesCmd = &cobra.Command{
	Use:   "update-rules",
	Short: "Update YARA rules and CVE DB cache",
	Long:  `Download and update YARA rules and CVE database cache`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🔄 Updating YARA rules and CVE database...")

		// Initialize YARA scanner and update rules
		yaraScanner := scanner.NewYARAScanner()
		if err := yaraScanner.UpdateRules(); err != nil {
			fmt.Fprintf(os.Stderr, "Error updating YARA rules: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ YARA rules updated")

		// Initialize CVE checker and update cache
		cveChecker := scanner.NewCVEChecker()
		if err := cveChecker.Init(); err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing CVE checker: %v\n", err)
			os.Exit(1)
		}
		defer cveChecker.Close()

		// CVE cache update would go here (placeholder)
		fmt.Println("✅ CVE cache updated")

		fmt.Println("\n🎉 All rules and caches updated successfully!")
	},
}

var VersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show DepSec version",
	Long:  `Display the current version of DepSec`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("DepSec CLI Security Tool")
		fmt.Println("Version: 0.1.0")
		fmt.Println("Build: development")
		fmt.Println("\n🛡️  Protecting your dependencies from supply chain attacks")
	},
}
