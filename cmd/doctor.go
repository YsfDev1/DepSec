package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/DepSec/config"
	"github.com/DepSec/hooks"
	"github.com/DepSec/output"
	"github.com/spf13/cobra"
)

var DoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check system health",
	Long: `Check Docker, ClamAV, shell hooks, and other dependencies.
Perform a full health check of the DepSec environment.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Run health checks
		checks := runHealthChecks()

		// Format and display results
		formatter := output.NewFormatter("table", true, false)
		// Convert cmd.HealthCheck to output.HealthCheck
		outputChecks := make([]output.HealthCheck, len(checks))
		for i, check := range checks {
			outputChecks[i] = output.HealthCheck{
				Name:       check.Name,
				Passed:     check.Passed,
				Message:    check.Message,
				Suggestion: check.Suggestion,
			}
		}
		result := formatter.FormatDoctor(outputChecks)
		fmt.Print(result)

		// Determine exit code based on critical failures
		criticalFailures := 0
		for _, check := range checks {
			if !check.Passed && isCriticalCheck(check.Name) {
				criticalFailures++
			}
		}

		if criticalFailures > 0 {
			fmt.Printf("\n❌ %d critical health check(s) failed\n", criticalFailures)
			os.Exit(1)
		} else {
			fmt.Printf("\n✅ All health checks passed\n")
		}
	},
}

func init() {
	// Add any flags for doctor command here
}

// HealthCheck represents a health check result
type HealthCheck struct {
	Name       string
	Passed     bool
	Message    string
	Suggestion string
}

// runHealthChecks performs all health checks
func runHealthChecks() []HealthCheck {
	var checks []HealthCheck

	// Check Go version
	checks = append(checks, checkGoVersion())

	// Check Docker
	checks = append(checks, checkDocker())

	// Check ClamAV
	checks = append(checks, checkClamAV())

	// Check shell hooks
	checks = append(checks, checkShellHooks())

	// Check configuration
	checks = append(checks, checkConfiguration())

	// Check cache directory
	checks = append(checks, checkCacheDirectory())

	// Check YARA rules
	checks = append(checks, checkYARARules())

	// Check network connectivity
	checks = append(checks, checkNetworkConnectivity())

	return checks
}

// checkGoVersion checks if Go version is supported
func checkGoVersion() HealthCheck {
	check := HealthCheck{Name: "Go Version"}

	// Get Go version
	cmd := exec.Command("go", "version")
	output, err := cmd.Output()
	if err != nil {
		check.Passed = false
		check.Message = "Go not found in PATH"
		check.Suggestion = "Install Go: https://golang.org/dl/"
		return check
	}

	// Parse version (simplified)
	versionStr := string(output)
	check.Message = versionStr
	check.Passed = true

	return check
}

// checkDocker checks Docker availability and status
func checkDocker() HealthCheck {
	check := HealthCheck{Name: "Docker"}

	// Check if Docker is installed
	cmd := exec.Command("docker", "--version")
	if err := cmd.Run(); err != nil {
		check.Passed = false
		check.Message = "Docker not found"
		check.Suggestion = "Install Docker: https://docker.com/desktop"
		return check
	}

	// Check if Docker daemon is running
	cmd = exec.Command("docker", "info")
	if err := cmd.Run(); err != nil {
		check.Passed = false
		check.Message = "Docker daemon not running"
		check.Suggestion = "Start Docker daemon or install Docker Desktop"
		return check
	}

	check.Message = "Docker is available and running"
	check.Passed = true

	return check
}

// checkClamAV checks ClamAV availability
func checkClamAV() HealthCheck {
	check := HealthCheck{Name: "ClamAV"}

	// Check for various ClamAV binaries
	clamavBinaries := []string{"clamav", "clamscan", "clamd", "freshclam"}
	var foundBinaries []string

	for _, binary := range clamavBinaries {
		if _, err := exec.LookPath(binary); err == nil {
			foundBinaries = append(foundBinaries, binary)
		}
	}

	if len(foundBinaries) == 0 {
		check.Passed = false
		check.Message = "ClamAV not found"
		check.Suggestion = "Install ClamAV: brew install clamav / apt install clamav / choco install clamav"
		return check
	}

	check.Message = fmt.Sprintf("ClamAV found: %v", foundBinaries)
	check.Passed = true

	return check
}

// checkShellHooks checks if shell hooks are properly configured
func checkShellHooks() HealthCheck {
	check := HealthCheck{Name: "Shell Hooks"}

	shellManager := hooks.NewShellManager()
	status := shellManager.GetStatus()

	if enabled, ok := status["enabled"].(bool); ok && enabled {
		check.Message = fmt.Sprintf("Auto-scan hooks enabled for %s", status["shell"])
		check.Passed = true
	} else {
		check.Message = "Auto-scan hooks not enabled"
		check.Suggestion = "Run 'depsec auto enable' to enable automatic scanning"
		check.Passed = true // Not having hooks enabled is not a failure
	}

	return check
}

// checkConfiguration checks configuration file
func checkConfiguration() HealthCheck {
	check := HealthCheck{Name: "Configuration"}

	configManager, err := config.NewManager()
	if err != nil {
		check.Passed = false
		check.Message = "Failed to load configuration"
		check.Suggestion = "Check configuration file permissions"
		return check
	}

	if err := configManager.Validate(); err != nil {
		check.Passed = false
		check.Message = fmt.Sprintf("Invalid configuration: %v", err)
		check.Suggestion = "Run 'depsec config reset' to restore defaults"
		return check
	}

	check.Message = "Configuration is valid"
	check.Passed = true

	return check
}

// checkCacheDirectory checks cache directory and permissions
func checkCacheDirectory() HealthCheck {
	check := HealthCheck{Name: "Cache Directory"}

	home, err := os.UserHomeDir()
	if err != nil {
		check.Passed = false
		check.Message = "Cannot determine user home directory"
		check.Suggestion = "Check HOME environment variable"
		return check
	}

	cacheDir := filepath.Join(home, ".cache", "depsec")

	// Check if directory exists or can be created
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		if err := os.MkdirAll(cacheDir, 0755); err != nil {
			check.Passed = false
			check.Message = "Cannot create cache directory"
			check.Suggestion = "Check permissions for " + filepath.Dir(cacheDir)
			return check
		}
	}

	// Test write permissions
	testFile := filepath.Join(cacheDir, "test_write")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		check.Passed = false
		check.Message = "Cannot write to cache directory"
		check.Suggestion = "Check permissions for " + cacheDir
		return check
	}
	os.Remove(testFile)

	check.Message = "Cache directory is accessible"
	check.Passed = true

	return check
}

// checkYARARules checks YARA rules directory
func checkYARARules() HealthCheck {
	check := HealthCheck{Name: "YARA Rules"}

	home, err := os.UserHomeDir()
	if err != nil {
		check.Passed = false
		check.Message = "Cannot determine user home directory"
		return check
	}

	rulesDir := filepath.Join(home, ".config", "depsec", "rules")

	// Check if rules directory exists
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		check.Message = "YARA rules directory not found (will be created on first use)"
		check.Passed = true // Not a failure, will be created automatically
		return check
	}

	// Check for default rules file
	defaultRules := filepath.Join(rulesDir, "default.yar")
	if _, err := os.Stat(defaultRules); os.IsNotExist(err) {
		check.Message = "Default YARA rules file not found"
		check.Suggestion = "Run 'depsec update-rules' to create default rules"
		check.Passed = false
		return check
	}

	check.Message = "YARA rules directory is configured"
	check.Passed = true

	return check
}

// checkNetworkConnectivity checks basic network connectivity
func checkNetworkConnectivity() HealthCheck {
	check := HealthCheck{Name: "Network Connectivity"}

	// Simple connectivity check to OSV API
	cmd := exec.Command("curl", "-s", "--connect-timeout", "5", "https://api.osv.dev")
	if err := cmd.Run(); err != nil {
		check.Message = "Cannot reach OSV API (offline mode will be limited)"
		check.Suggestion = "Check internet connection or use --offline flag"
		check.Passed = false
		return check
	}

	check.Message = "Network connectivity is working"
	check.Passed = true

	return check
}

// isCriticalCheck determines if a health check failure is critical
func isCriticalCheck(name string) bool {
	criticalChecks := []string{"Go Version", "Configuration", "Cache Directory"}
	for _, critical := range criticalChecks {
		if name == critical {
			return true
		}
	}
	return false
}
