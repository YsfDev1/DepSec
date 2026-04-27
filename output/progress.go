package output

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ProgressState represents the current state of a scan progress
type ProgressState struct {
	CurrentPackage string
	CurrentVersion string
	CurrentLayer   string
	TotalPackages  int
	Completed      int
	Findings       int
	Errors         int
	StartTime      time.Time
}

// ProgressModel is a Bubbletea model for displaying scan progress
type ProgressModel struct {
	state    ProgressState
	spinner  spinner.Model
	quitting bool
	done     bool
}

// NewProgressModel creates a new progress model
func NewProgressModel(totalPackages int) ProgressModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(colorPrimary)

	return ProgressModel{
		state: ProgressState{
			TotalPackages: totalPackages,
			StartTime:     time.Now(),
		},
		spinner: s,
	}
}

// Init initializes the progress model
func (m ProgressModel) Init() tea.Cmd {
	return m.spinner.Tick
}

// Update handles messages
func (m ProgressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			m.quitting = true
			return m, tea.Quit
		}
	case ProgressMsg:
		m.state.CurrentPackage = msg.Package
		m.state.CurrentVersion = msg.Version
		m.state.CurrentLayer = msg.Layer
		if msg.Completed {
			m.state.Completed++
		}
		if msg.Finding {
			m.state.Findings++
		}
		if msg.Error {
			m.state.Errors++
		}
	case DoneMsg:
		m.done = true
		return m, tea.Quit
	default:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

// View renders the progress UI
func (m ProgressModel) View() string {
	if m.done {
		return ""
	}

	var s strings.Builder

	// Header
	s.WriteString(HeaderStyle.Render("🔒 SecChain Security Scan"))
	s.WriteString("\n\n")

	// Progress stats
	if m.state.TotalPackages > 0 {
		progress := float64(m.state.Completed) / float64(m.state.TotalPackages)
		percent := int(progress * 100)

		bar := renderProgressBar(progress, 40)
		s.WriteString(fmt.Sprintf("Progress: %s %d%% (%d/%d packages)\n",
			bar, percent, m.state.Completed, m.state.TotalPackages))
		s.WriteString("\n")
	}

	// Current operation
	if m.state.CurrentPackage != "" {
		s.WriteString(MutedTextStyle.Render("Scanning: "))
		s.WriteString(fmt.Sprintf("%s@%s\n", m.state.CurrentPackage, m.state.CurrentVersion))

		if m.state.CurrentLayer != "" {
			s.WriteString(MutedTextStyle.Render("Layer: "))
			s.WriteString(fmt.Sprintf("%s %s\n", GetLayerIcon(m.state.CurrentLayer), m.state.CurrentLayer))
		}

		s.WriteString("\n")
		s.WriteString(m.spinner.View())
		s.WriteString(" " + MutedTextStyle.Render("Working..."))
		s.WriteString("\n")
	}

	// Summary stats
	if m.state.Findings > 0 || m.state.Errors > 0 {
		s.WriteString("\n")
		if m.state.Findings > 0 {
			s.WriteString(WarningTextStyle.Render(fmt.Sprintf("⚠️  %d finding(s) detected", m.state.Findings)))
			s.WriteString("\n")
		}
		if m.state.Errors > 0 {
			s.WriteString(ErrorTextStyle.Render(fmt.Sprintf("❌ %d error(s)", m.state.Errors)))
			s.WriteString("\n")
		}
	}

	// Elapsed time
	elapsed := time.Since(m.state.StartTime).Round(time.Second)
	s.WriteString("\n")
	s.WriteString(MutedTextStyle.Render(fmt.Sprintf("Elapsed: %s (press 'q' to cancel)", elapsed)))

	return s.String()
}

// ProgressMsg updates the progress state
type ProgressMsg struct {
	Package   string
	Version   string
	Layer     string
	Completed bool
	Finding   bool
	Error     bool
}

// DoneMsg signals the scan is complete
type DoneMsg struct{}

// SimpleProgressWriter is a non-interactive progress writer for CI environments
type SimpleProgressWriter struct {
	writer         io.Writer
	state          ProgressState
	lastUpdate     time.Time
	updateInterval time.Duration
}

// NewSimpleProgressWriter creates a simple progress writer
func NewSimpleProgressWriter(w io.Writer, totalPackages int) *SimpleProgressWriter {
	return &SimpleProgressWriter{
		writer: w,
		state: ProgressState{
			TotalPackages: totalPackages,
			StartTime:     time.Now(),
		},
		updateInterval: 2 * time.Second,
	}
}

// Update updates the progress state and prints if needed
func (p *SimpleProgressWriter) Update(pkg, version, layer string, completed, finding, hasError bool) {
	p.state.CurrentPackage = pkg
	p.state.CurrentVersion = version
	p.state.CurrentLayer = layer
	if completed {
		p.state.Completed++
	}
	if finding {
		p.state.Findings++
	}
	if hasError {
		p.state.Errors++
	}

	now := time.Now()
	if now.Sub(p.lastUpdate) >= p.updateInterval || completed {
		p.print()
		p.lastUpdate = now
	}
}

// print outputs the current progress
func (p *SimpleProgressWriter) print() {
	if p.state.TotalPackages == 0 {
		return
	}

	progress := float64(p.state.Completed) / float64(p.state.TotalPackages)
	percent := int(progress * 100)
	elapsed := time.Since(p.state.StartTime).Round(time.Second)

	fmt.Fprintf(p.writer, "[%3d%%] %d/%d packages | %d findings | %d errors | %s elapsed\n",
		percent, p.state.Completed, p.state.TotalPackages, p.state.Findings, p.state.Errors, elapsed)
}

// Finish prints the final summary
func (p *SimpleProgressWriter) Finish() {
	elapsed := time.Since(p.state.StartTime).Round(time.Second)
	fmt.Fprintf(p.writer, "\nScan complete: %d packages scanned in %s\n", p.state.Completed, elapsed)
	if p.state.Findings > 0 {
		fmt.Fprintf(p.writer, "Findings: %d\n", p.state.Findings)
	}
	if p.state.Errors > 0 {
		fmt.Fprintf(p.writer, "Errors: %d\n", p.state.Errors)
	}
}

// renderProgressBar creates a visual progress bar
func renderProgressBar(progress float64, width int) string {
	filled := int(progress * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}

	empty := width - filled

	var bar strings.Builder
	bar.WriteString("[")
	if filled > 0 {
		bar.WriteString(lipgloss.NewStyle().Background(colorPrimary).Foreground(colorWhite).Render(strings.Repeat("█", filled)))
	}
	if empty > 0 {
		bar.WriteString(strings.Repeat("░", empty))
	}
	bar.WriteString("]")

	return bar.String()
}

// ScanProgressCallback is a function called during scanning to report progress
type ScanProgressCallback func(pkg, version, layer string, completed, finding, hasError bool)

// NoopProgressCallback is a callback that does nothing (for non-interactive mode)
func NoopProgressCallback(pkg, version, layer string, completed, finding, hasError bool) {}
