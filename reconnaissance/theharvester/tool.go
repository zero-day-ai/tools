package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "theharvester"
	ToolVersion     = "1.0.0"
	ToolDescription = "Email/Domain OSINT Tool - Harvests email addresses, subdomains, and employee information from search engines and public sources for reconnaissance"
)

// ToolImpl implements the theHarvester tool
type ToolImpl struct{}

// NewTool creates a new theHarvester tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"osint",
			"email-harvesting",
			"subdomain-enumeration",
			"T1589.002", // Gather Victim Identity Information: Email Addresses
			"T1591",     // Gather Victim Org Information
		}).
		SetInputSchema(InputSchema()).
		SetOutputSchema(OutputSchema()).
		SetExecuteFunc((&ToolImpl{}).Execute)

	t, _ := tool.New(cfg)
	return &toolWithHealth{Tool: t, impl: &ToolImpl{}}
}

// toolWithHealth wraps the tool to add custom health checks
type toolWithHealth struct {
	tool.Tool
	impl *ToolImpl
}

func (t *toolWithHealth) Health(ctx context.Context) types.HealthStatus {
	return t.impl.Health(ctx)
}

// Execute runs theHarvester with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract required domain parameter
	domain, ok := input["domain"].(string)
	if !ok || domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	// Extract optional parameters
	sources := extractStringSlice(input, "sources")
	limit := extractInt(input, "limit", 500)
	start := extractInt(input, "start", 0)

	// Create temporary directory for output
	tempDir, err := os.MkdirTemp("", "theharvester-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	outputFile := filepath.Join(tempDir, "output")

	// Build theHarvester command arguments
	args := buildTheHarvesterArgs(domain, sources, limit, start, outputFile)

	// Execute theHarvester using python3
	result, err := exec.Run(ctx, exec.Config{
		Command: "python3",
		Args:    append([]string{"-m", "theHarvester"}, args...),
		Timeout: 5 * time.Minute, // Default timeout
	})

	if err != nil {
		return nil, fmt.Errorf("theHarvester execution failed: %w", err)
	}

	// theHarvester returns exit code 0 even with some errors, check stderr for critical failures
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("theHarvester failed with exit code %d: %s", result.ExitCode, string(result.Stderr))
	}

	// Parse output based on available format
	// theHarvester can output JSON or XML, we'll try JSON first, then XML
	var harvesterData *HarvesterOutput

	// Try JSON output
	jsonFile := outputFile + ".json"
	if _, err := os.Stat(jsonFile); err == nil {
		harvesterData, err = parseJSONOutput(jsonFile)
		if err != nil {
			return nil, fmt.Errorf("failed to parse JSON output: %w", err)
		}
	} else {
		// Try XML output
		xmlFile := outputFile + ".xml"
		if _, err := os.Stat(xmlFile); err == nil {
			harvesterData, err = parseXMLOutput(xmlFile)
			if err != nil {
				return nil, fmt.Errorf("failed to parse XML output: %w", err)
			}
		} else {
			// No structured output found, parse from stdout
			harvesterData = parseTextOutput(string(result.Stdout))
		}
	}

	// Calculate scan duration
	scanDuration := time.Since(startTime)

	// Build output
	output := map[string]any{
		"domain":            domain,
		"emails":            harvesterData.Emails,
		"hosts":             harvesterData.Hosts,
		"ips":               harvesterData.IPs,
		"interesting_urls":  harvesterData.URLs,
		"people":            harvesterData.People,
		"sources_queried":   determineSourcesQueried(sources),
		"scan_time_ms":      scanDuration.Milliseconds(),
	}

	return output, nil
}

// Health checks if theHarvester is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Check if python3 is available
	if !exec.BinaryExists("python3") {
		return types.NewUnhealthyStatus("python3 not found in PATH", nil)
	}

	// Try to execute theHarvester with --help to verify it's installed
	result, err := exec.Run(ctx, exec.Config{
		Command: "python3",
		Args:    []string{"-m", "theHarvester", "--help"},
		Timeout: 5 * time.Second,
	})

	if err != nil || result.ExitCode != 0 {
		return types.NewUnhealthyStatus("theHarvester is not installed or not accessible via 'python3 -m theHarvester'", map[string]any{
			"error": err,
		})
	}

	return types.NewHealthyStatus("theHarvester is operational")
}

// buildTheHarvesterArgs constructs command-line arguments for theHarvester
func buildTheHarvesterArgs(domain string, sources []string, limit, start int, outputFile string) []string {
	args := []string{
		"-d", domain, // domain to search
		"-l", fmt.Sprintf("%d", limit), // limit results
	}

	// Add sources if specified
	if len(sources) > 0 {
		args = append(args, "-b", strings.Join(sources, ","))
	} else {
		// Use default comprehensive sources
		args = append(args, "-b", "all")
	}

	// Add start offset if specified
	if start > 0 {
		args = append(args, "-s", fmt.Sprintf("%d", start))
	}

	// Output file with format (JSON preferred, XML as fallback)
	args = append(args, "-f", outputFile)

	return args
}

// HarvesterOutput represents parsed theHarvester output
type HarvesterOutput struct {
	Emails []string
	Hosts  []string
	IPs    []string
	URLs   []string
	People []string
}

// HarvesterJSON represents theHarvester JSON output structure
type HarvesterJSON struct {
	Emails []string `json:"emails"`
	Hosts  []string `json:"hosts"`
	IPs    []string `json:"ips"`
	URLs   []string `json:"interesting_urls"`
}

// parseJSONOutput parses theHarvester JSON output
func parseJSONOutput(filePath string) (*HarvesterOutput, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var jsonData HarvesterJSON
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return nil, err
	}

	return &HarvesterOutput{
		Emails: jsonData.Emails,
		Hosts:  jsonData.Hosts,
		IPs:    jsonData.IPs,
		URLs:   jsonData.URLs,
		People: []string{}, // JSON format doesn't include people
	}, nil
}

// HarvesterXML represents theHarvester XML output structure
type HarvesterXML struct {
	XMLName xml.Name `xml:"theHarvester"`
	Emails  []string `xml:"email"`
	Hosts   []string `xml:"host"`
	IPs     []string `xml:"ip"`
	URLs    []string `xml:"url"`
}

// parseXMLOutput parses theHarvester XML output
func parseXMLOutput(filePath string) (*HarvesterOutput, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var xmlData HarvesterXML
	if err := xml.Unmarshal(data, &xmlData); err != nil {
		return nil, err
	}

	return &HarvesterOutput{
		Emails: xmlData.Emails,
		Hosts:  xmlData.Hosts,
		IPs:    xmlData.IPs,
		URLs:   xmlData.URLs,
		People: []string{}, // XML format doesn't include people
	}, nil
}

// parseTextOutput parses theHarvester text output (fallback)
func parseTextOutput(output string) *HarvesterOutput {
	result := &HarvesterOutput{
		Emails: []string{},
		Hosts:  []string{},
		IPs:    []string{},
		URLs:   []string{},
		People: []string{},
	}

	lines := strings.Split(output, "\n")
	section := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Detect sections
		if strings.Contains(line, "[*] Emails found:") {
			section = "emails"
			continue
		} else if strings.Contains(line, "[*] Hosts found:") {
			section = "hosts"
			continue
		} else if strings.Contains(line, "[*] IPs found:") {
			section = "ips"
			continue
		} else if strings.Contains(line, "[*] Interesting Urls found:") {
			section = "urls"
			continue
		} else if strings.Contains(line, "[*] People found:") {
			section = "people"
			continue
		}

		// Skip section headers and separator lines
		if strings.HasPrefix(line, "[*]") || strings.HasPrefix(line, "---") {
			continue
		}

		// Add to appropriate section
		switch section {
		case "emails":
			if strings.Contains(line, "@") {
				result.Emails = append(result.Emails, line)
			}
		case "hosts":
			result.Hosts = append(result.Hosts, line)
		case "ips":
			result.IPs = append(result.IPs, line)
		case "urls":
			result.URLs = append(result.URLs, line)
		case "people":
			result.People = append(result.People, line)
		}
	}

	return result
}

// extractStringSlice safely extracts a string slice from input map
func extractStringSlice(input map[string]any, key string) []string {
	if val, ok := input[key]; ok {
		if slice, ok := val.([]any); ok {
			result := make([]string, 0, len(slice))
			for _, item := range slice {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			return result
		}
	}
	return nil
}

// extractInt safely extracts an integer from input map with default
func extractInt(input map[string]any, key string, defaultVal int) int {
	if val, ok := input[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		case int64:
			return int(v)
		}
	}
	return defaultVal
}

// determineSourcesQueried returns the list of sources that were queried
func determineSourcesQueried(sources []string) []string {
	if len(sources) > 0 {
		return sources
	}
	// When using "all", theHarvester queries multiple sources
	return []string{"all"}
}
