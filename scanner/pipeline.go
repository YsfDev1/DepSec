package scanner

import (
	"context"
	"fmt"
)

// Pipeline orchestrates the layered scanning process
type Pipeline struct {
	cveChecker      *CVEChecker
	metadataChecker *MetadataChecker
	sandboxScanner  *SandboxScanner
	yaraScanner     *YARAScanner
	clamavScanner   *ClamAVScanner
}

// ScanResult represents the result of scanning a package
type ScanResult struct {
	Package   string
	Version   string
	Ecosystem string
	Findings  []Finding
	Clean     bool
}

// Finding represents a security finding
type Finding struct {
	Layer    string
	Severity string
	Reason   string
	Details  string
}

// NewPipeline creates a new scanning pipeline
func NewPipeline() *Pipeline {
	pipeline := &Pipeline{
		cveChecker:      NewCVEChecker(),
		metadataChecker: NewMetadataChecker(),
		sandboxScanner:  NewSandboxScanner(),
		yaraScanner:     NewYARAScanner(),
		clamavScanner:   NewClamAVScanner(),
	}
	
	// Initialize all components
	pipeline.cveChecker.Init()
	pipeline.metadataChecker.Init()
	pipeline.sandboxScanner.Init()
	pipeline.yaraScanner.Init()
	pipeline.clamavScanner.Init()
	
	return pipeline
}

// ScanPackage runs the full scanning pipeline on a package
func (p *Pipeline) ScanPackage(ctx context.Context, pkg, version, ecosystem string) (*ScanResult, error) {
	result := &ScanResult{
		Package:   pkg,
		Version:   version,
		Ecosystem: ecosystem,
		Findings:  []Finding{},
		Clean:     true,
	}

	// Layer 1: CVE Matching
	if findings, err := p.cveChecker.CheckCVEs(ctx, pkg, version, ecosystem); err == nil {
		result.Findings = append(result.Findings, findings...)
	}

	// Layer 2: Metadata Anomaly Detection
	if findings, err := p.metadataChecker.CheckMetadata(ctx, pkg, version, ecosystem); err == nil {
		result.Findings = append(result.Findings, findings...)
	}

	// Layer 3: Sandbox Scan (if Docker is available)
	if p.sandboxScanner.IsAvailable() {
		if findings, err := p.sandboxScanner.ScanInSandbox(ctx, pkg, version, ecosystem); err == nil {
			result.Findings = append(result.Findings, findings...)
		}
	}

	// Layer 4: YARA Rule Matching (inside sandbox)
	if p.yaraScanner.IsAvailable() {
		if findings, err := p.yaraScanner.ScanWithYARA(ctx, pkg, version, ecosystem); err == nil {
			result.Findings = append(result.Findings, findings...)
		}
	}

	// Layer 5: ClamAV Scanning (inside sandbox)
	if p.clamavScanner.IsAvailable() {
		if findings, err := p.clamavScanner.ScanWithClamAV(ctx, pkg, version, ecosystem); err == nil {
			result.Findings = append(result.Findings, findings...)
		}
	}

	// Determine if package is clean
	result.Clean = len(result.Findings) == 0

	return result, nil
}

// ScanProject scans a local project directory
func (p *Pipeline) ScanProject(ctx context.Context, projectPath string) ([]*ScanResult, error) {
	// Resolve dependencies from project
	deps, err := p.resolveDependencies(projectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve dependencies: %w", err)
	}

	var results []*ScanResult
	for _, dep := range deps {
		result, err := p.ScanPackage(ctx, dep.Name, dep.Version, dep.Ecosystem)
		if err != nil {
			return nil, fmt.Errorf("failed to scan package %s: %w", dep.Name, err)
		}
		results = append(results, result)
	}

	return results, nil
}

func (p *Pipeline) resolveDependencies(projectPath string) ([]Dependency, error) {
	resolver := NewResolver()
	return resolver.ResolveDependencies(projectPath)
}

// Dependency represents a package dependency
type Dependency struct {
	Name      string
	Version   string
	Ecosystem string
}
