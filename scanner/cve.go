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
	db        *sql.DB
	cacheTTL  time.Duration
	offline   bool
}

// CVE represents a Common Vulnerabilities and Exposures record
type CVE struct {
	ID          string    `json:"id"`
	Summary     string    `json:"summary"`
	Severity    string    `json:"severity"`
	Published   time.Time `json:"published"`
	Modified    time.Time `json:"modified"`
	Affected    []string  `json:"affected"`
	References  []string  `json:"references"`
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
	// Map ecosystem to OSV ecosystem names
	ecosystemMap := map[string]string{
		"node":   "npm",
		"python": "pypi",
		"rust":   "cargo",
		"go":     "go",
		"ruby":   "rubygems",
	}

	osvEcosystem, ok := ecosystemMap[ecosystem]
	if !ok {
		return nil, fmt.Errorf("unsupported ecosystem: %s", ecosystem)
	}

	// Build OSV query
	query := map[string]interface{}{
		"package": map[string]interface{}{
			"name":      pkg,
			"ecosystem": osvEcosystem,
		},
		"version": version,
	}

	queryBytes, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OSV query: %w", err)
	}

	// Make HTTP request to OSV API
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.osv.dev/v1/query", bytes.NewReader(queryBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create OSV request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "DepSec/0.1.0")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute OSV request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API returned status %d: %s", resp.StatusCode, string(body))
	}

	var osvResponse struct {
		Vulns []struct {
			ID      string `json:"id"`
			Summary string `json:"summary"`
			Details string `json:"details"`
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			Published string `json:"published"`
			Modified  string `json:"modified"`
			Affected []struct {
				Package map[string]string `json:"package"`
				Ranges []struct {
					Type   string `json:"type"`
					Events []struct {
						Introduced string `json:"introduced"`
						Fixed      string `json:"fixed"`
					} `json:"events"`
				} `json:"ranges"`
				DatabaseSpecific struct {
					CWE []string `json:"cwe"`
				} `json:"database_specific"`
			} `json:"affected"`
		} `json:"vulns"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&osvResponse); err != nil {
		return nil, fmt.Errorf("failed to decode OSV response: %w", err)
	}

	var cves []CVE
	for _, vuln := range osvResponse.Vulns {
		severity := "MEDIUM"
		if len(vuln.Severity) > 0 {
			// Parse CVSS score to determine severity
			for _, sev := range vuln.Severity {
				if sev.Type == "CVSS_V3" {
					score := sev.Score
					if score == "9.0" || score == "9.8" || score == "10.0" {
						severity = "CRITICAL"
					} else if score == "7.5" || score == "7.8" || score == "8.0" || score == "8.8" {
						severity = "HIGH"
					} else if score == "5.3" || score == "5.4" || score == "5.5" || score == "5.9" || score == "6.0" || score == "6.1" || score == "6.5" {
						severity = "MEDIUM"
					} else {
						severity = "LOW"
					}
					break
				}
			}
		}

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

		// Add more detailed affected versions
		for _, affected := range vuln.Affected {
			if affectedPkg, ok := affected.Package["name"]; ok && affectedPkg == pkg {
				for _, r := range affected.Ranges {
					if r.Type == "SEMVER" {
						for _, event := range r.Events {
							if event.Fixed != "" {
								cve.Affected = append(cve.Affected, fmt.Sprintf("%s < %s", pkg, event.Fixed))
							}
						}
					}
				}
			}
		}

		cves = append(cves, cve)
	}

	return cves, nil
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
