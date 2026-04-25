package cache

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Cache handles local caching of scan results and CVE data
type Cache struct {
	db       *sql.DB
	cacheDir string
}

// NewCache creates a new cache instance
func NewCache() (*Cache, error) {
	cacheDir := getCacheDir()
	
	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Open SQLite database
	dbPath := filepath.Join(cacheDir, "depsec.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open cache database: %w", err)
	}

	cache := &Cache{
		db:       db,
		cacheDir: cacheDir,
	}

	// Initialize database schema
	if err := cache.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize cache schema: %w", err)
	}

	return cache, nil
}

// initSchema creates the necessary database tables
func (c *Cache) initSchema() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS scan_results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			package_name TEXT NOT NULL,
			version TEXT NOT NULL,
			ecosystem TEXT NOT NULL,
			findings TEXT NOT NULL,
			clean BOOLEAN NOT NULL,
			scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(package_name, version, ecosystem)
		)`,
		`CREATE TABLE IF NOT EXISTS cve_cache (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			package_name TEXT NOT NULL,
			version TEXT NOT NULL,
			ecosystem TEXT NOT NULL,
			cve_data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(package_name, version, ecosystem)
		)`,
		`CREATE TABLE IF NOT EXISTS metadata_cache (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			package_name TEXT NOT NULL,
			version TEXT NOT NULL,
			ecosystem TEXT NOT NULL,
			metadata TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(package_name, version, ecosystem)
		)`,
	}

	for _, query := range queries {
		if _, err := c.db.Exec(query); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	return nil
}

// GetScanResult retrieves a cached scan result
func (c *Cache) GetScanResult(pkg, version, ecosystem string) (*CachedScanResult, error) {
	query := `
	SELECT findings, clean, scanned_at FROM scan_results 
	WHERE package_name = ? AND version = ? AND ecosystem = ? 
	AND scanned_at > datetime('now', '-24 hours')`

	var result CachedScanResult
	var findingsJSON string
	var scannedAt string

	err := c.db.QueryRow(query, pkg, version, ecosystem).Scan(&findingsJSON, &result.Clean, &scannedAt)
	if err == sql.ErrNoRows {
		return nil, nil // Not found or expired
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query scan result: %w", err)
	}

	result.Package = pkg
	result.Version = version
	result.Ecosystem = ecosystem
	result.ScannedAt, _ = time.Parse("2006-01-02 15:04:05", scannedAt)

	// Parse findings JSON (simplified)
	result.FindingsJSON = findingsJSON

	return &result, nil
}

// SetScanResult stores a scan result in cache
func (c *Cache) SetScanResult(pkg, version, ecosystem string, findingsJSON string, clean bool) error {
	query := `
	INSERT OR REPLACE INTO scan_results (package_name, version, ecosystem, findings, clean)
	VALUES (?, ?, ?, ?, ?)`

	_, err := c.db.Exec(query, pkg, version, ecosystem, findingsJSON, clean)
	return err
}

// GetCVEData retrieves cached CVE data
func (c *Cache) GetCVEData(pkg, version, ecosystem string) (string, error) {
	query := `
	SELECT cve_data FROM cve_cache 
	WHERE package_name = ? AND version = ? AND ecosystem = ? 
	AND created_at > datetime('now', '-24 hours')`

	var cveData string
	err := c.db.QueryRow(query, pkg, version, ecosystem).Scan(&cveData)
	if err == sql.ErrNoRows {
		return "", nil // Not found or expired
	}
	if err != nil {
		return "", fmt.Errorf("failed to query CVE data: %w", err)
	}

	return cveData, nil
}

// SetCVEData stores CVE data in cache
func (c *Cache) SetCVEData(pkg, version, ecosystem, cveData string) error {
	query := `
	INSERT OR REPLACE INTO cve_cache (package_name, version, ecosystem, cve_data)
	VALUES (?, ?, ?, ?)`

	_, err := c.db.Exec(query, pkg, version, ecosystem, cveData)
	return err
}

// GetMetadata retrieves cached metadata
func (c *Cache) GetMetadata(pkg, version, ecosystem string) (string, error) {
	query := `
	SELECT metadata FROM metadata_cache 
	WHERE package_name = ? AND version = ? AND ecosystem = ? 
	AND created_at > datetime('now', '-24 hours')`

	var metadata string
	err := c.db.QueryRow(query, pkg, version, ecosystem).Scan(&metadata)
	if err == sql.ErrNoRows {
		return "", nil // Not found or expired
	}
	if err != nil {
		return "", fmt.Errorf("failed to query metadata: %w", err)
	}

	return metadata, nil
}

// SetMetadata stores metadata in cache
func (c *Cache) SetMetadata(pkg, version, ecosystem, metadata string) error {
	query := `
	INSERT OR REPLACE INTO metadata_cache (package_name, version, ecosystem, metadata)
	VALUES (?, ?, ?, ?)`

	_, err := c.db.Exec(query, pkg, version, ecosystem, metadata)
	return err
}

// Cleanup removes expired cache entries
func (c *Cache) Cleanup() error {
	// Remove entries older than 24 hours
	queries := []string{
		"DELETE FROM scan_results WHERE scanned_at < datetime('now', '-24 hours')",
		"DELETE FROM cve_cache WHERE created_at < datetime('now', '-24 hours')",
		"DELETE FROM metadata_cache WHERE created_at < datetime('now', '-24 hours')",
	}

	for _, query := range queries {
		if _, err := c.db.Exec(query); err != nil {
			return fmt.Errorf("failed to cleanup cache: %w", err)
		}
	}

	return nil
}

// GetStats returns cache statistics
func (c *Cache) GetStats() (*CacheStats, error) {
	stats := &CacheStats{}

	// Count scan results
	err := c.db.QueryRow("SELECT COUNT(*) FROM scan_results").Scan(&stats.ScanResults)
	if err != nil {
		return nil, fmt.Errorf("failed to count scan results: %w", err)
	}

	// Count CVE entries
	err = c.db.QueryRow("SELECT COUNT(*) FROM cve_cache").Scan(&stats.CVEEntries)
	if err != nil {
		return nil, fmt.Errorf("failed to count CVE entries: %w", err)
	}

	// Count metadata entries
	err = c.db.QueryRow("SELECT COUNT(*) FROM metadata_cache").Scan(&stats.MetadataEntries)
	if err != nil {
		return nil, fmt.Errorf("failed to count metadata entries: %w", err)
	}

	// Get cache directory size
	size, err := c.getCacheSize()
	if err != nil {
		return nil, fmt.Errorf("failed to get cache size: %w", err)
	}
	stats.SizeBytes = size

	return stats, nil
}

// getCacheSize calculates the total size of cache directory
func (c *Cache) getCacheSize() (int64, error) {
	var size int64 = 0

	err := filepath.Walk(c.cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})

	return size, err
}

// Close closes the cache database
func (c *Cache) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// CachedScanResult represents a cached scan result
type CachedScanResult struct {
	Package      string
	Version      string
	Ecosystem    string
	FindingsJSON string
	Clean        bool
	ScannedAt    time.Time
}

// CacheStats represents cache statistics
type CacheStats struct {
	ScanResults     int
	CVEEntries      int
	MetadataEntries int
	SizeBytes       int64
}

// getCacheDir returns the cache directory path
func getCacheDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "depsec")
}
