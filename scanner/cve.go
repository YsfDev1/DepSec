package scanner

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// CVEChecker handles CVE matching using OSV and NVD APIs
type CVEChecker struct {
	db       *sql.DB
	cacheTTL time.Duration
	offline  bool
}

// CVE represents a Common Vulnerabilities and Exposures record
type CVE struct {
	ID         string    `json:"id"`
	Summary    string    `json:"summary"`
	Severity   string    `json:"severity"`
	Published  time.Time `json:"published"`
	Modified   time.Time `json:"modified"`
	Affected   []string  `json:"affected"`
	References []string  `json:"references"`
}

// NewCVEChecker creates a new CVE checker
func NewCVEChecker() *CVEChecker {
	return &CVEChecker{
		cacheTTL: 24 * time.Hour,
	}
}

// Init initializes the CVE checker and database
func (c *CVEChecker) Init() error {
	cacheDir := getCacheDir()

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	dbPath := filepath.Join(cacheDir, "cve.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open CVE database: %w", err)
	}
	c.db = db

	// Create tables
	if err := c.createTables(); err != nil {
		return fmt.Errorf("failed to create CVE tables: %w", err)
	}

	return nil
}

// createTables creates the necessary database tables
func (c *CVEChecker) createTables() error {
	query := `
	CREATE TABLE IF NOT EXISTS cve_cache (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		package_name TEXT NOT NULL,
		version TEXT NOT NULL,
		ecosystem TEXT NOT NULL,
		cve_data TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(package_name, version, ecosystem)
	);`

	_, err := c.db.Exec(query)
	return err
}

// CheckCVEs checks for CVEs in a package
func (c *CVEChecker) CheckCVEs(ctx context.Context, pkg, version, ecosystem string) ([]Finding, error) {
	var findings []Finding

	// Check cache first
	if cached, err := c.getCachedCVEs(pkg, version, ecosystem); err == nil && cached != nil {
		return c.processCVEs(cached, pkg, version, ecosystem), nil
	}

	// If offline, return cached results or empty
	if c.offline {
		return findings, nil
	}

	// Query OSV API
	osvCVEs, err := c.queryOSV(ctx, pkg, version, ecosystem)
	if err != nil {
		return nil, fmt.Errorf("failed to query OSV API: %w", err)
	}

	// Query NVD API
	nvdCVEs, err := c.queryNVD(ctx, pkg, version, ecosystem)
	if err != nil {
		// NVD is optional, continue with OSV results
		nvdCVEs = []CVE{}
	}

	// Combine and cache results
	allCVEs := append(osvCVEs, nvdCVEs...)
	if err := c.cacheCVEs(pkg, version, ecosystem, allCVEs); err != nil {
		// Cache failure is not critical
		fmt.Printf("Warning: failed to cache CVEs for %s: %v\n", pkg, err)
	}

	return c.processCVEs(allCVEs, pkg, version, ecosystem), nil
}

// queryOSV queries the OSV API for CVEs
func (c *CVEChecker) queryOSV(ctx context.Context, pkg, version, ecosystem string) ([]CVE, error) {
	osvEcosystem, err := c.mapEcosystemToOSV(ecosystem)
	if err != nil {
		return nil, err
	}

	query, err := c.buildOSVQuery(pkg, osvEcosystem, version)
	if err != nil {
		return nil, err
	}

	resp, err := c.makeOSVRequest(ctx, query)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API returned status %d: %s", resp.StatusCode, string(body))
	}

	osvResponse, err := c.parseOSVResponse(resp)
	if err != nil {
		return nil, err
	}

	return c.buildCVEResults(osvResponse, pkg, version), nil
}

// mapEcosystemToOSV maps ecosystem names to OSV ecosystem names
func (c *CVEChecker) mapEcosystemToOSV(ecosystem string) (string, error) {
	ecosystemMap := map[string]string{
		"node":   "npm",
		"python": "pypi",
		"rust":   "cargo",
		"go":     "go",
		"ruby":   "rubygems",
	}

	osvEcosystem, ok := ecosystemMap[ecosystem]
	if !ok {
		return "", fmt.Errorf("unsupported ecosystem: %s", ecosystem)
	}
	return osvEcosystem, nil
}

// buildOSVQuery builds the OSV API query
func (c *CVEChecker) buildOSVQuery(pkg, osvEcosystem, version string) ([]byte, error) {
	query := map[string]interface{}{
		"package": map[string]interface{}{
			"name":      pkg,
			"ecosystem": osvEcosystem,
		},
		"version": version,
	}

	return json.Marshal(query)
}

// makeOSVRequest makes the HTTP request to OSV API
func (c *CVEChecker) makeOSVRequest(ctx context.Context, query []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.osv.dev/v1/query", bytes.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("failed to create OSV request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "DepSec/0.1.0")

	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

// parseOSVResponse parses the OSV API response
func (c *CVEChecker) parseOSVResponse(resp *http.Response) (*osvResponse, error) {
	var osvResp osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("failed to decode OSV response: %w", err)
	}
	return &osvResp, nil
}

// osvResponse represents the OSV API response structure

type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

// osvVuln represents a vulnerability from OSV API
type osvVuln struct {
	ID        string        `json:"id"`
	Summary   string        `json:"summary"`
	Details   string        `json:"details"`
	Severity  []osvSeverity `json:"severity"`
	Published string        `json:"published"`
	Modified  string        `json:"modified"`
	Affected  []osvAffected `json:"affected"`
}

// osvSeverity represents severity information
type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// osvAffected represents affected package information
type osvAffected struct {
	Package          map[string]string   `json:"package"`
	Ranges           []osvRange          `json:"ranges"`
	DatabaseSpecific osvDatabaseSpecific `json:"database_specific"`
}

// osvRange represents version ranges
type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

// osvEvent represents version events
type osvEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

// osvDatabaseSpecific represents database-specific information
type osvDatabaseSpecific struct {
	CWE []string `json:"cwe"`
}

// buildCVEResults converts OSV response to CVE results
func (c *CVEChecker) buildCVEResults(osvResp *osvResponse, pkg, version string) []CVE {
	var cves []CVE
	for _, vuln := range osvResp.Vulns {
		cve := c.buildCVEResult(vuln, pkg, version)
		cves = append(cves, cve)
	}
	return cves
}

// buildCVEResult builds a single CVE result from OSV vulnerability
func (c *CVEChecker) buildCVEResult(vuln osvVuln, pkg, version string) CVE {
	severity := c.determineSeverity(vuln.Severity)
	published, _ := time.Parse(time.RFC3339, vuln.Published)
	modified, _ := time.Parse(time.RFC3339, vuln.Modified)

	cve := CVE{
		ID:         vuln.ID,
		Summary:    vuln.Summary,
		Severity:   severity,
		Published:  published,
		Modified:   modified,
		Affected:   []string{pkg + "@" + version},
		References: []string{},
	}

	cve.Affected = c.processAffectedVersions(vuln.Affected, pkg, cve.Affected)
	return cve
}

// determineSeverity determines severity from CVSS score
func (c *CVEChecker) determineSeverity(severities []osvSeverity) string {
	if len(severities) == 0 {
		return "MEDIUM"
	}

	for _, sev := range severities {
		if sev.Type == "CVSS_V3" {
			return c.mapScoreToSeverity(sev.Score)
		}
	}
	return "MEDIUM"
}

// mapScoreToSeverity maps CVSS score to severity level
func (c *CVEChecker) mapScoreToSeverity(score string) string {
	switch score {
	case "9.0", "9.8", "10.0":
		return "CRITICAL"
	case "7.5", "7.8", "8.0", "8.8":
		return "HIGH"
	case "5.3", "5.4", "5.5", "5.9", "6.0", "6.1", "6.5":
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// processAffectedVersions processes affected version ranges
func (c *CVEChecker) processAffectedVersions(affected []osvAffected, pkg string, baseAffected []string) []string {
	for _, aff := range affected {
		if affectedPkg, ok := aff.Package["name"]; ok && affectedPkg == pkg {
			for _, r := range aff.Ranges {
				if r.Type == "SEMVER" {
					for _, event := range r.Events {
						if event.Fixed != "" {
							baseAffected = append(baseAffected, fmt.Sprintf("%s < %s", pkg, event.Fixed))
						}
					}
				}
			}
		}
	}
	return baseAffected
}

// queryNVD queries the NVD API for CVEs (simplified implementation)
func (c *CVEChecker) queryNVD(ctx context.Context, pkg, version, ecosystem string) ([]CVE, error) {
	// NVD API implementation would go here
	// For now, return empty as OSV API is primary
	return []CVE{}, nil
}

// getCachedCVEs retrieves cached CVEs from database
func (c *CVEChecker) getCachedCVEs(pkg, version, ecosystem string) ([]CVE, error) {
	if c.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	query := `
	SELECT cve_data FROM cve_cache 
	WHERE package_name = ? AND version = ? AND ecosystem = ? 
	AND created_at > datetime('now', '-24 hours')`

	var cveData string
	err := c.db.QueryRow(query, pkg, version, ecosystem).Scan(&cveData)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var cves []CVE
	if err := json.Unmarshal([]byte(cveData), &cves); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cached CVEs: %w", err)
	}

	return cves, nil
}

// cacheCVEs stores CVEs in the cache database
func (c *CVEChecker) cacheCVEs(pkg, version, ecosystem string, cves []CVE) error {
	if c.db == nil {
		return fmt.Errorf("database not initialized")
	}

	cveData, err := json.Marshal(cves)
	if err != nil {
		return fmt.Errorf("failed to marshal CVEs for caching: %w", err)
	}

	query := `
	INSERT OR REPLACE INTO cve_cache (package_name, version, ecosystem, cve_data)
	VALUES (?, ?, ?, ?)`

	_, err = c.db.Exec(query, pkg, version, ecosystem, string(cveData))
	return err
}

// processCVEs converts CVEs to findings
func (c *CVEChecker) processCVEs(cves []CVE, pkg, version, ecosystem string) []Finding {
	var findings []Finding

	for _, cve := range cves {
		findings = append(findings, Finding{
			Layer:    "CVE",
			Severity: cve.Severity,
			Reason:   fmt.Sprintf("CVE %s: %s", cve.ID, cve.Summary),
			Details:  fmt.Sprintf("Package: %s@%s, Published: %s", pkg, version, cve.Published.Format("2006-01-02")),
		})
	}

	return findings
}

// SetOffline sets the offline mode
func (c *CVEChecker) SetOffline(offline bool) {
	c.offline = offline
}

// Close closes the database connection
func (c *CVEChecker) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// Helper function to get cache directory
func getCacheDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "depsec")
}
