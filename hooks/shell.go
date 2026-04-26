package hooks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ShellManager manages shell hook injection and removal
type ShellManager struct {
	ShellType string `json:"shell_type"`
	ShellRC   string `json:"shell_rc"`
}

// NewShellManager creates a new shell manager
func NewShellManager() *ShellManager {
	return &ShellManager{
		ShellType: detectShell(),
		ShellRC:   getShellRC(),
	}
}

// detectShell detects the current shell
func detectShell() string {
	shell := os.Getenv("SHELL")
	if shell == "" {
		return "zsh" // default fallback
	}

	return filepath.Base(shell)
}

// getShellRC gets the appropriate shell RC file
func getShellRC() string {
	home, _ := os.UserHomeDir()
	shell := detectShell()

	switch shell {
	case "bash":
		return filepath.Join(home, ".bashrc")
	case "zsh":
		return filepath.Join(home, ".zshrc")
	case "fish":
		return filepath.Join(home, ".config/fish/config.fish")
	default:
		return filepath.Join(home, ".zshrc") // fallback
	}
}

// EnableAutoScan enables auto-scan by injecting shell hooks
func (s *ShellManager) EnableAutoScan() error {
	// Read current shell RC content
	content, err := os.ReadFile(s.ShellRC)
	if err != nil {
		return fmt.Errorf("failed to read shell config: %w", err)
	}

	currentContent := string(content)

	// Check if hooks are already enabled
	if s.isHooksEnabled(currentContent) {
		return fmt.Errorf("auto-scan hooks already enabled")
	}

	// Generate hooks for the detected shell
	hooks := s.generateHooks()

	// Append hooks to shell RC
	newContent := currentContent + "\n" + hooks + "\n"

	// Write back to shell RC
	if err := os.WriteFile(s.ShellRC, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write shell config: %w", err)
	}

	return nil
}

// DisableAutoScan disables auto-scan by removing shell hooks
func (s *ShellManager) DisableAutoScan() error {
	// Read current shell RC content
	content, err := os.ReadFile(s.ShellRC)
	if err != nil {
		return fmt.Errorf("failed to read shell config: %w", err)
	}

	currentContent := string(content)

	// Remove DepSec hooks
	newContent := s.removeHooks(currentContent)

	// Write back to shell RC
	if err := os.WriteFile(s.ShellRC, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write shell config: %w", err)
	}

	return nil
}

// IsEnabled checks if auto-scan hooks are enabled
func (s *ShellManager) IsEnabled() bool {
	content, err := os.ReadFile(s.ShellRC)
	if err != nil {
		return false
	}

	return s.isHooksEnabled(string(content))
}

// generateHooks generates shell hooks for auto-scan
func (s *ShellManager) generateHooks() string {
	switch s.ShellType {
	case "bash", "zsh":
		return s.generateBashHooks()
	case "fish":
		return s.generateFishHooks()
	default:
		return s.generateBashHooks()
	}
}

// generateBashHooks generates bash/zsh hooks
func (s *ShellManager) generateBashHooks() string {
	return `# DepSec Auto-Scan Hooks (added by depsec auto enable)
# DO NOT EDIT MANUALLY - use 'depsec auto disable' to remove

# npm hook
npm() {
    if [[ "$1" == "install" || "$1" == "i" ]]; then
        for pkg in "${@:2}"; do
            if [[ "$pkg" != -* ]]; then
                depsec scan --pkg "$pkg" --ecosystem node || {
                    echo "⚠️  DepSec scan failed for $pkg"
                    echo "Install anyway? [y/N]"
                    read -r response
                    if [[ ! "$response" =~ ^[Yy]$ ]]; then
                        echo "Installation cancelled"
                        return 1
                    fi
                }
            fi
        done
    fi
    command npm "$@"
}

# pip hook
pip() {
    if [[ "$1" == "install" ]]; then
        for pkg in "${@:2}"; do
            if [[ "$pkg" != -* ]]; then
                depsec scan --pkg "$pkg" --ecosystem python || {
                    echo "⚠️  DepSec scan failed for $pkg"
                    echo "Install anyway? [y/N]"
                    read -r response
                    if [[ ! "$response" =~ ^[Yy]$ ]]; then
                        echo "Installation cancelled"
                        return 1
                    fi
                }
            fi
        done
    fi
    command pip "$@"
}

# cargo hook
cargo() {
    if [[ "$1" == "add" || "$1" == "install" ]]; then
        for pkg in "${@:2}"; do
            if [[ "$pkg" != -* ]]; then
                depsec scan --pkg "$pkg" --ecosystem rust || {
                    echo "⚠️  DepSec scan failed for $pkg"
                    echo "Install anyway? [y/N]"
                    read -r response
                    if [[ ! "$response" =~ ^[Yy]$ ]]; then
                        echo "Installation cancelled"
                        return 1
                    fi
                }
            fi
        done
    fi
    command cargo "$@"
}

# go get hook
go() {
    if [[ "$1" == "get" || "$1" == "install" ]]; then
        for pkg in "${@:2}"; do
            if [[ "$pkg" != -* ]]; then
                depsec scan --pkg "$pkg" --ecosystem go || {
                    echo "⚠️  DepSec scan failed for $pkg"
                    echo "Install anyway? [y/N]"
                    read -r response
                    if [[ ! "$response" =~ ^[Yy]$ ]]; then
                        echo "Installation cancelled"
                        return 1
                    fi
                }
            fi
        done
    fi
    command go "$@"
}

# gem hook
gem() {
    if [[ "$1" == "install" ]]; then
        for pkg in "${@:2}"; do
            if [[ "$pkg" != -* ]]; then
                depsec scan --pkg "$pkg" --ecosystem ruby || {
                    echo "⚠️  DepSec scan failed for $pkg"
                    echo "Install anyway? [y/N]"
                    read -r response
                    if [[ ! "$response" =~ ^[Yy]$ ]]; then
                        echo "Installation cancelled"
                        return 1
                    fi
                }
            fi
        done
    fi
    command gem "$@"
}

# End DepSec Auto-Scan Hooks`
}

// generateFishHooks generates fish shell hooks
func (s *ShellManager) generateFishHooks() string {
	return `# DepSec Auto-Scan Hooks (added by depsec auto enable)
# DO NOT EDIT MANUALLY - use 'depsec auto disable' to remove

function npm
    if test "$argv[1]" = "install" -o "$argv[1]" = "i"
        for pkg in $argv[2..]
            if not string match -q "-*" $pkg
                if not depsec scan --pkg $pkg --ecosystem node
                    echo "⚠️  DepSec scan failed for $pkg"
                    echo "Install anyway? [y/N]"
                    read -l response
                    if not string match -qr "^[Yy]$" $response
                        echo "Installation cancelled"
                        return 1
                    end
                end
            end
        end
    end
    command npm $argv
end

function pip
    if test "$argv[1]" = "install"
        for pkg in $argv[2..]
            if not string match -q "-*" $pkg
                if not depsec scan --pkg $pkg --ecosystem python
                    echo "⚠️  DepSec scan failed for $pkg"
                    echo "Install anyway? [y/N]"
                    read -l response
                    if not string match -qr "^[Yy]$" $response
                        echo "Installation cancelled"
                        return 1
                    end
                end
            end
        end
    end
    command pip $argv
end

function cargo
    if test "$argv[1]" = "add" -o "$argv[1]" = "install"
        for pkg in $argv[2..]
            if not string match -q "-*" $pkg
                if not depsec scan --pkg $pkg --ecosystem rust
                    echo "⚠️  DepSec scan failed for $pkg"
                    echo "Install anyway? [y/N]"
                    read -l response
                    if not string match -qr "^[Yy]$" $response
                        echo "Installation cancelled"
                        return 1
                    end
                end
            end
        end
    end
    command cargo $argv
end

function go
    if test "$argv[1]" = "get" -o "$argv[1]" = "install"
        for pkg in $argv[2..]
            if not string match -q "-*" $pkg
                if not depsec scan --pkg $pkg --ecosystem go
                    echo "⚠️  DepSec scan failed for $pkg"
                    echo "Install anyway? [y/N]"
                    read -l response
                    if not string match -qr "^[Yy]$" $response
                        echo "Installation cancelled"
                        return 1
                    end
                end
            end
        end
    end
    command go $argv
end

function gem
    if test "$argv[1]" = "install"
        for pkg in $argv[2..]
            if not string match -q "-*" $pkg
                if not depsec scan --pkg $pkg --ecosystem ruby
                    echo "⚠️  DepSec scan failed for $pkg"
                    echo "Install anyway? [y/N]"
                    read -l response
                    if not string match -qr "^[Yy]$" $response
                        echo "Installation cancelled"
                        return 1
                    end
                end
            end
        end
    end
    command gem $argv
end

# End DepSec Auto-Scan Hooks`
}

// isHooksEnabled checks if DepSec hooks are already enabled
func (s *ShellManager) isHooksEnabled(content string) bool {
	return strings.Contains(content, "# DepSec Auto-Scan Hooks")
}

// removeHooks removes DepSec hooks from shell config
func (s *ShellManager) removeHooks(content string) string {
	startMarker := "# DepSec Auto-Scan Hooks"
	endMarker := "# End DepSec Auto-Scan Hooks"

	startIndex := strings.Index(content, startMarker)
	if startIndex == -1 {
		return content // hooks not found
	}

	endIndex := strings.Index(content[startIndex:], endMarker)
	if endIndex == -1 {
		return content // malformed hooks
	}

	endIndex += startIndex + len(endMarker)

	// Remove the hooks section
	newContent := content[:startIndex] + content[endIndex:]

	// Clean up extra newlines
	newContent = strings.ReplaceAll(newContent, "\n\n\n", "\n\n")

	return newContent
}

// GetStatus returns the current status of auto-scan hooks
func (s *ShellManager) GetStatus() map[string]interface{} {
	return map[string]interface{}{
		"enabled": s.IsEnabled(),
		"shell":   s.ShellType,
		"config":  s.ShellRC,
		"hooks":   []string{"npm", "pip", "cargo", "go", "gem"},
	}
}
