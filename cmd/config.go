package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/YsfDev1/SecChain/config"
	"github.com/spf13/cobra"
)

var ConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration",
	Long:  `View and modify SecChain configuration settings`,
}

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Long:  `Display all current configuration values`,
	Run: func(cmd *cobra.Command, args []string) {
		configManager, err := config.NewManager()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
			os.Exit(1)
		}

		config := configManager.Get()

		fmt.Println("SecChain Configuration:")
		fmt.Printf("  Mode: %s\n", config.Mode)
		fmt.Printf("  Min Severity: %s\n", config.MinSeverity)
		fmt.Printf("  Offline: %t\n", config.Offline)
		fmt.Printf("  Auto-Scan Enabled: %t\n", config.AutoScan.Enabled)
		fmt.Printf("  Auto-Scan Ecosystems: %s\n", strings.Join(config.AutoScan.Ecosystems, ", "))
		fmt.Printf("  Docker Enabled: %t\n", config.Docker.Enabled)
		fmt.Printf("  ClamAV Enabled: %t\n", config.ClamAV.Enabled)
		fmt.Printf("  YARA Enabled: %t\n", config.YARA.Enabled)
		fmt.Printf("  Cache Enabled: %t\n", config.Cache.Enabled)
		fmt.Printf("  Output Format: %s\n", config.Output.Format)
		fmt.Printf("  Show Clean: %t\n", config.Output.ShowClean)
		fmt.Printf("  Verbose: %t\n", config.Output.Verbose)
	},
}

var setCmd = &cobra.Command{
	Use:   "set",
	Short: "Set configuration value",
	Long:  `Set a specific configuration value`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]
		value := args[1]

		configManager, err := config.NewManager()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
			os.Exit(1)
		}

		if err := configManager.Set(key, value); err != nil {
			fmt.Fprintf(os.Stderr, "Error setting configuration: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("✅ Set %s = %s\n", key, value)
	},
}

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset configuration",
	Long:  `Reset configuration to default values`,
	Run: func(cmd *cobra.Command, args []string) {
		configManager, err := config.NewManager()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
			os.Exit(1)
		}

		if err := configManager.Reset(); err != nil {
			fmt.Fprintf(os.Stderr, "Error resetting configuration: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("✅ Configuration reset to defaults")
	},
}

func init() {
	ConfigCmd.AddCommand(showCmd)
	ConfigCmd.AddCommand(setCmd)
	ConfigCmd.AddCommand(resetCmd)
}
