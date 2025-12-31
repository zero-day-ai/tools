package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	sdkinput "github.com/zero-day-ai/sdk/input"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/health"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "sqlmap"
	ToolVersion     = "1.0.0"
	ToolDescription = "SQL injection detection and exploitation tool using sqlmap in batch mode"
	BinaryName      = "sqlmap"
)

// ToolImpl implements the sqlmap tool
type ToolImpl struct{}

// NewTool creates a new sqlmap tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"initial-access",
			"sql-injection",
			"exploitation",
			"T1190", // Exploit Public-Facing Application
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

// Execute implements the tool execution logic
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Create temporary output directory for sqlmap results
	outputDir, err := os.MkdirTemp("", "sqlmap-output-*")
	if err != nil {
		return nil, toolerr.New(ToolName, "create-temp-dir", toolerr.ErrCodeExecutionFailed, "failed to create temporary output directory").WithCause(err)
	}
	defer os.RemoveAll(outputDir) // Clean up after execution

	// Build sqlmap command arguments
	args := buildSqlmapArgs(input, outputDir)

	// Get timeout (default to 5 minutes)
	timeout := sdkinput.GetTimeout(input, "timeout", sdkinput.DefaultTimeout())

	// Execute sqlmap
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, "sqlmap execution failed").
			WithCause(err).
			WithDetails(map[string]any{
				"exit_code": result.ExitCode,
				"stderr":    string(result.Stderr),
			})
	}

	// Parse sqlmap output
	output, parseErr := parseSqlmapOutput(outputDir, result.Stdout, result.Stderr)
	if parseErr != nil {
		// Return what we can parse even if there's an error
		output["parse_error"] = parseErr.Error()
	}

	// Add scan time
	output["scan_time_ms"] = time.Since(startTime).Milliseconds()

	return output, nil
}

// Health checks if sqlmap binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildSqlmapArgs constructs the command-line arguments for sqlmap
func buildSqlmapArgs(input map[string]any, outputDir string) []string {
	args := []string{
		"--batch",           // Always use batch mode (non-interactive)
		"--output-dir", outputDir, // Store results in temp directory
		"--flush-session",   // Flush session files for fresh scan
	}

	// Required: Target URL
	url := sdkinput.GetString(input, "url", "")
	if url != "" {
		args = append(args, "-u", url)
	}

	// Optional: POST data
	if data := sdkinput.GetString(input, "data", ""); data != "" {
		args = append(args, "--data", data)
	}

	// Optional: Cookie
	if cookie := sdkinput.GetString(input, "cookie", ""); cookie != "" {
		args = append(args, "--cookie", cookie)
	}

	// Optional: HTTP method
	if method := sdkinput.GetString(input, "method", ""); method != "" {
		args = append(args, "--method", method)
	}

	// Optional: Specific parameter to test
	if param := sdkinput.GetString(input, "param", ""); param != "" {
		args = append(args, "-p", param)
	}

	// Optional: Force DBMS
	if dbms := sdkinput.GetString(input, "dbms", ""); dbms != "" {
		args = append(args, "--dbms", dbms)
	}

	// Optional: Test level (1-5)
	level := sdkinput.GetInt(input, "level", 1)
	args = append(args, "--level", fmt.Sprintf("%d", level))

	// Optional: Risk level (1-3)
	risk := sdkinput.GetInt(input, "risk", 1)
	args = append(args, "--risk", fmt.Sprintf("%d", risk))

	// Optional: Technique
	if technique := sdkinput.GetString(input, "technique", ""); technique != "" {
		args = append(args, "--technique", technique)
	}

	// Optional: Enumerate databases
	if sdkinput.GetBool(input, "dbs", false) {
		args = append(args, "--dbs")
	}

	// Optional: Dump data
	if sdkinput.GetBool(input, "dump", false) {
		args = append(args, "--dump")
	}

	return args
}

// parseSqlmapOutput parses sqlmap output from files and stdout/stderr
func parseSqlmapOutput(outputDir string, stdout, stderr []byte) (map[string]any, error) {
	output := map[string]any{
		"vulnerable":      false,
		"injection_point": map[string]any{},
		"dbms":            "",
		"databases":       []string{},
		"current_user":    "",
		"current_db":      "",
		"is_dba":          false,
		"data_extracted":  map[string]any{},
	}

	// Parse stdout/stderr for key information
	stdoutStr := string(stdout)
	stderrStr := string(stderr)
	combinedOutput := stdoutStr + "\n" + stderrStr

	// Check if vulnerability was found
	if strings.Contains(combinedOutput, "sqlmap identified the following injection point") ||
		strings.Contains(combinedOutput, "Parameter:") && strings.Contains(combinedOutput, "Type:") {
		output["vulnerable"] = true

		// Extract injection point details
		injectionPoint := parseInjectionPoint(combinedOutput)
		if len(injectionPoint) > 0 {
			output["injection_point"] = injectionPoint
		}
	}

	// Extract DBMS information
	if dbms := extractDBMS(combinedOutput); dbms != "" {
		output["dbms"] = dbms
	}

	// Extract current user
	if user := extractCurrentUser(combinedOutput); user != "" {
		output["current_user"] = user
	}

	// Extract current database
	if db := extractCurrentDB(combinedOutput); db != "" {
		output["current_db"] = db
	}

	// Extract DBA status
	if isDBA := extractDBAStatus(combinedOutput); isDBA {
		output["is_dba"] = true
	}

	// Parse databases from output files
	databases, err := parseDatabasesFromFiles(outputDir)
	if err == nil && len(databases) > 0 {
		output["databases"] = databases
	}

	// Parse dumped data from CSV files
	dumpedData, err := parseDumpedDataFromFiles(outputDir)
	if err == nil && len(dumpedData) > 0 {
		output["data_extracted"] = dumpedData
	}

	return output, nil
}

// parseInjectionPoint extracts injection point details from sqlmap output
func parseInjectionPoint(output string) map[string]any {
	injectionPoint := map[string]any{}

	// Extract parameter name
	paramRe := regexp.MustCompile(`Parameter:\s+([^\s]+)`)
	if matches := paramRe.FindStringSubmatch(output); len(matches) > 1 {
		injectionPoint["parameter"] = matches[1]
	}

	// Extract injection type
	typeRe := regexp.MustCompile(`Type:\s+(.+)`)
	if matches := typeRe.FindStringSubmatch(output); len(matches) > 1 {
		injectionPoint["type"] = strings.TrimSpace(matches[1])
	}

	// Extract payload (first line after "Payload:")
	payloadRe := regexp.MustCompile(`Payload:\s+(.+)`)
	if matches := payloadRe.FindStringSubmatch(output); len(matches) > 1 {
		injectionPoint["payload"] = strings.TrimSpace(matches[1])
	}

	return injectionPoint
}

// extractDBMS extracts the database type from sqlmap output
func extractDBMS(output string) string {
	// Look for "back-end DBMS:" pattern
	dbmsRe := regexp.MustCompile(`back-end DBMS:\s+([^\n]+)`)
	if matches := dbmsRe.FindStringSubmatch(output); len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}

	// Alternative pattern: "web application technology:"
	techRe := regexp.MustCompile(`web server operating system:\s+[^\n]*\nweb application technology:\s+[^\n]*\nback-end DBMS:\s+([^\n]+)`)
	if matches := techRe.FindStringSubmatch(output); len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}

	return ""
}

// extractCurrentUser extracts the current database user from output
func extractCurrentUser(output string) string {
	userRe := regexp.MustCompile(`current user:\s+'([^']+)'`)
	if matches := userRe.FindStringSubmatch(output); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractCurrentDB extracts the current database name from output
func extractCurrentDB(output string) string {
	dbRe := regexp.MustCompile(`current database:\s+'([^']+)'`)
	if matches := dbRe.FindStringSubmatch(output); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractDBAStatus checks if current user is DBA
func extractDBAStatus(output string) bool {
	return strings.Contains(output, "current user is DBA: True") ||
		strings.Contains(output, "current user is DBA:True")
}

// parseDatabasesFromFiles parses database names from sqlmap output files
func parseDatabasesFromFiles(outputDir string) ([]string, error) {
	databases := []string{}

	// Look for log files that might contain database enumeration
	logPattern := filepath.Join(outputDir, "**", "log")
	logFiles, err := filepath.Glob(logPattern)
	if err != nil {
		return databases, err
	}

	for _, logFile := range logFiles {
		content, err := os.ReadFile(logFile)
		if err != nil {
			continue
		}

		// Parse databases from log content
		lines := strings.Split(string(content), "\n")
		inDatabaseSection := false
		for _, line := range lines {
			if strings.Contains(line, "available databases") {
				inDatabaseSection = true
				continue
			}
			if inDatabaseSection && strings.HasPrefix(line, "[*] ") {
				dbName := strings.TrimSpace(strings.TrimPrefix(line, "[*] "))
				if dbName != "" {
					databases = append(databases, dbName)
				}
			}
			if inDatabaseSection && !strings.HasPrefix(line, "[*] ") && strings.TrimSpace(line) != "" {
				inDatabaseSection = false
			}
		}
	}

	return databases, nil
}

// parseDumpedDataFromFiles parses dumped data from CSV files created by sqlmap
func parseDumpedDataFromFiles(outputDir string) (map[string]any, error) {
	dumpedData := map[string]any{}

	// Look for CSV files in the dump directory
	csvPattern := filepath.Join(outputDir, "**", "dump", "**", "*.csv")
	csvFiles, err := filepath.Glob(csvPattern)
	if err != nil {
		return dumpedData, err
	}

	for _, csvFile := range csvFiles {
		// Extract table name from file path
		tableName := strings.TrimSuffix(filepath.Base(csvFile), ".csv")

		// Parse CSV file
		file, err := os.Open(csvFile)
		if err != nil {
			continue
		}
		defer file.Close()

		reader := csv.NewReader(file)
		records, err := reader.ReadAll()
		if err != nil {
			continue
		}

		if len(records) > 0 {
			// First row is headers, rest are data
			dumpedData[tableName] = map[string]any{
				"columns": records[0],
				"rows":    records[1:],
				"count":   len(records) - 1,
			}
		}
	}

	return dumpedData, nil
}

// Helper function to read file content
func readFileContent(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// Helper function to scan file line by line
func scanFileLines(filePath string, handler func(string)) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		handler(scanner.Text())
	}

	return scanner.Err()
}
