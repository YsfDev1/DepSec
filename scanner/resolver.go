package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Resolver handles dependency resolution for different ecosystems
type Resolver struct {
	// Add any configuration or cache here
}

// NewResolver creates a new dependency resolver
func NewResolver() *Resolver {
	return &Resolver{}
}

// ResolveDependencies resolves dependencies from a project directory
func (r *Resolver) ResolveDependencies(projectPath string) ([]Dependency, error) {
	var allDeps []Dependency

	// Check for Node.js (package-lock.json)
	if nodeDeps, err := r.resolveNodeDependencies(projectPath); err == nil {
		allDeps = append(allDeps, nodeDeps...)
	}

	// Check for Python (requirements.txt, Pipfile.lock)
	if pythonDeps, err := r.resolvePythonDependencies(projectPath); err == nil {
		allDeps = append(allDeps, pythonDeps...)
	}

	// Check for Rust (Cargo.lock)
	if rustDeps, err := r.resolveRustDependencies(projectPath); err == nil {
		allDeps = append(allDeps, rustDeps...)
	}

	// Check for Go (go.mod, go.sum)
	if goDeps, err := r.resolveGoDependencies(projectPath); err == nil {
		allDeps = append(allDeps, goDeps...)
	}

	// Check for Ruby (Gemfile.lock)
	if rubyDeps, err := r.resolveRubyDependencies(projectPath); err == nil {
		allDeps = append(allDeps, rubyDeps...)
	}

	return allDeps, nil
}

// resolveNodeDependencies resolves Node.js dependencies from package-lock.json
func (r *Resolver) resolveNodeDependencies(projectPath string) ([]Dependency, error) {
	lockFile := filepath.Join(projectPath, "package-lock.json")
	data, err := os.ReadFile(lockFile)
	if err != nil {
		return nil, fmt.Errorf("no package-lock.json found")
	}

	// Parse package-lock.json (handle lockfileVersion 1, 2, and 3)
	var packageLock struct {
		LockfileVersion int `json:"lockfileVersion"`
		Dependencies    map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}

	if err := json.Unmarshal(data, &packageLock); err != nil {
		return nil, fmt.Errorf("failed to parse package-lock.json: %w", err)
	}

	var deps []Dependency

	// Handle lockfileVersion 3 (npm 7+)
	if packageLock.LockfileVersion >= 3 {
		for name, info := range packageLock.Packages {
			// Skip root package
			if name == "" {
				continue
			}
			deps = append(deps, Dependency{
				Name:      name,
				Version:   info.Version,
				Ecosystem: "node",
			})
		}
	} else if packageLock.LockfileVersion == 2 {
		// Handle lockfileVersion 2 (npm 6)
		for name, info := range packageLock.Dependencies {
			deps = append(deps, Dependency{
				Name:      name,
				Version:   info.Version,
				Ecosystem: "node",
			})
		}
	} else {
		// Handle lockfileVersion 1 (npm 2-4) - nested structure
		var packageLockV1 struct {
			Dependencies map[string]struct {
				Version      string `json:"version"`
				Dependencies map[string]struct {
					Version string `json:"version"`
				} `json:"dependencies"`
			} `json:"dependencies"`
		}
		if err := json.Unmarshal(data, &packageLockV1); err == nil {
			for name, info := range packageLockV1.Dependencies {
				deps = append(deps, Dependency{
					Name:      name,
					Version:   info.Version,
					Ecosystem: "node",
				})
				// Handle nested dependencies
				for nestedName, nestedInfo := range info.Dependencies {
					deps = append(deps, Dependency{
						Name:      nestedName,
						Version:   nestedInfo.Version,
						Ecosystem: "node",
					})
				}
			}
		}
	}

	return deps, nil
}

// resolvePythonDependencies resolves Python dependencies from requirements.txt or pyproject.toml
func (r *Resolver) resolvePythonDependencies(projectPath string) ([]Dependency, error) {
	// Try pyproject.toml first (modern Python projects)
	pyprojectFile := filepath.Join(projectPath, "pyproject.toml")
	if deps, err := r.resolvePyprojectToml(pyprojectFile); err == nil {
		return deps, nil
	}

	// Try requirements.txt
	reqFile := filepath.Join(projectPath, "requirements.txt")
	data, err := os.ReadFile(reqFile)
	if err != nil {
		// Try Pipfile.lock
		pipfileLock := filepath.Join(projectPath, "Pipfile.lock")
		return r.resolvePipfileLock(pipfileLock)
	}

	// Parse requirements.txt (simple implementation)
	lines := splitLines(string(data))
	var deps []Dependency

	for _, line := range lines {
		line = trimComment(line)
		if line == "" {
			continue
		}

		// Simple parsing for "package==version" format
		if parts := splitVersion(line); len(parts) == 2 {
			deps = append(deps, Dependency{
				Name:      parts[0],
				Version:   parts[1],
				Ecosystem: "python",
			})
		}
	}

	return deps, nil
}

// resolvePipfileLock resolves dependencies from Pipfile.lock
func (r *Resolver) resolvePipfileLock(pipfileLock string) ([]Dependency, error) {
	data, err := os.ReadFile(pipfileLock)
	if err != nil {
		return nil, fmt.Errorf("no Python requirements file found")
	}

	var pipfile struct {
		Packages    map[string]string `json:"packages"`
		DevPackages map[string]string `json:"dev-packages"`
	}

	if err := json.Unmarshal(data, &pipfile); err != nil {
		return nil, fmt.Errorf("failed to parse Pipfile.lock: %w", err)
	}

	var deps []Dependency
	for name, version := range pipfile.Packages {
		deps = append(deps, Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "python",
		})
	}

	return deps, nil
}

// resolvePyprojectToml resolves dependencies from pyproject.toml
func (r *Resolver) resolvePyprojectToml(pyprojectFile string) ([]Dependency, error) {
	data, err := os.ReadFile(pyprojectFile)
	if err != nil {
		return nil, fmt.Errorf("no pyproject.toml found")
	}

	// Simple pyproject.toml parsing (would need TOML parser in production)
	lines := splitLines(string(data))
	var deps []Dependency
	inDependencies := false

	for _, line := range lines {
		line = trimComment(line)

		if strings.Contains(line, "[project.dependencies]") || strings.Contains(line, "[tool.poetry.dependencies]") {
			inDependencies = true
			continue
		}

		if inDependencies && strings.HasPrefix(line, "[") {
			// End of dependencies section
			break
		}

		if inDependencies && line != "" {
			// Simple parsing for "package==version" format
			if parts := splitVersion(line); len(parts) == 2 {
				deps = append(deps, Dependency{
					Name:      parts[0],
					Version:   parts[1],
					Ecosystem: "python",
				})
			}
		}
	}

	if len(deps) == 0 {
		return nil, fmt.Errorf("no dependencies found in pyproject.toml")
	}

	return deps, nil
}

// resolveRustDependencies resolves Rust dependencies from Cargo.lock
func (r *Resolver) resolveRustDependencies(projectPath string) ([]Dependency, error) {
	lockFile := filepath.Join(projectPath, "Cargo.lock")
	data, err := os.ReadFile(lockFile)
	if err != nil {
		return nil, fmt.Errorf("no Cargo.lock found")
	}

	var cargoLock struct {
		Package []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"package"`
	}

	if err := json.Unmarshal(data, &cargoLock); err != nil {
		return nil, fmt.Errorf("failed to parse Cargo.lock: %w", err)
	}

	var deps []Dependency
	for _, pkg := range cargoLock.Package {
		deps = append(deps, Dependency{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: "rust",
		})
	}

	return deps, nil
}

// resolveGoDependencies resolves Go dependencies from go.mod
func (r *Resolver) resolveGoDependencies(projectPath string) ([]Dependency, error) {
	goModFile := filepath.Join(projectPath, "go.mod")
	data, err := os.ReadFile(goModFile)
	if err != nil {
		return nil, fmt.Errorf("no go.mod found")
	}

	// Simple go.mod parsing (would need more sophisticated parsing in production)
	lines := splitLines(string(data))
	var deps []Dependency

	for _, line := range lines {
		line = trimComment(line)
		if !contains(line, "require") && contains(line, " ") {
			parts := splitFields(line)
			if len(parts) >= 2 && !contains(parts[0], "//") {
				deps = append(deps, Dependency{
					Name:      parts[0],
					Version:   parts[1],
					Ecosystem: "go",
				})
			}
		}
	}

	return deps, nil
}

// resolveRubyDependencies resolves Ruby dependencies from Gemfile.lock
func (r *Resolver) resolveRubyDependencies(projectPath string) ([]Dependency, error) {
	lockFile := filepath.Join(projectPath, "Gemfile.lock")
	data, err := os.ReadFile(lockFile)
	if err != nil {
		return nil, fmt.Errorf("no Gemfile.lock found")
	}

	// Simple Gemfile.lock parsing (would need more sophisticated parsing)
	lines := splitLines(string(data))
	var deps []Dependency
	inSpecs := false

	for _, line := range lines {
		line = trimComment(line)
		if contains(line, "specs:") {
			inSpecs = true
			continue
		}
		if inSpecs && contains(line, " ") {
			parts := splitFields(line)
			if len(parts) >= 2 {
				name := trimParentheses(parts[0])
				version := trimParentheses(parts[1])
				deps = append(deps, Dependency{
					Name:      name,
					Version:   version,
					Ecosystem: "ruby",
				})
			}
		}
	}

	return deps, nil
}

// Helper functions for parsing
func splitLines(s string) []string {
	return strings.Split(s, "\n")
}

func trimComment(s string) string {
	if idx := strings.Index(s, "#"); idx != -1 {
		return strings.TrimSpace(s[:idx])
	}
	return strings.TrimSpace(s)
}

func splitVersion(s string) []string {
	// Handle "package==version" or "package>=version" etc.
	for _, op := range []string{"==", ">=", "<=", ">", "<", "~=", "^"} {
		if strings.Contains(s, op) {
			return strings.SplitN(s, op, 2)
		}
	}

	// Handle "package version" (space separated)
	fields := strings.Fields(s)
	if len(fields) >= 2 {
		return []string{fields[0], fields[1]}
	}

	return []string{s}
}

func splitFields(s string) []string {
	return strings.Fields(s)
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func trimParentheses(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		return strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}
