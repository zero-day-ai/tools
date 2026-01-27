package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/zero-day-ai/sdk/api/gen/toolspb"
	"github.com/zero-day-ai/sdk/tool"
	"google.golang.org/protobuf/proto"
)

// Ensure ToolImpl implements StreamingTool
var _ tool.StreamingTool = (*ToolImpl)(nil)

// progressRegex matches nmap --stats-every percentage output
// Example: "Stats: 25.00% done"
var progressRegex = regexp.MustCompile(`(\d+(?:\.\d+)?)%\s+done`)

// StreamExecuteProto implements streaming nmap execution with real-time progress updates
// and graceful cancellation support.
func (t *ToolImpl) StreamExecuteProto(ctx context.Context, input proto.Message, stream tool.ToolStream) error {
	startTime := time.Now()

	// Type assert and validate input (same as ExecuteProto)
	req, ok := input.(*toolspb.NmapRequest)
	if !ok {
		return stream.Error(fmt.Errorf("invalid input type: expected *toolspb.NmapRequest, got %T", input), true)
	}

	// Validate required fields
	if len(req.Targets) == 0 {
		return stream.Error(fmt.Errorf("at least one target is required"), true)
	}

	if len(req.Args) == 0 {
		return stream.Error(fmt.Errorf("at least one argument is required"), true)
	}

	// Emit initial progress
	if err := stream.Progress(0, "init", "Starting nmap scan"); err != nil {
		return fmt.Errorf("failed to emit initial progress: %w", err)
	}

	// Build command arguments: -oX - (XML output to stdout) + --stats-every 5s + user args + targets
	args := []string{"-oX", "-", "--stats-every", "5s"}
	args = append(args, req.Args...)
	args = append(args, req.Targets...)

	cmd := exec.CommandContext(ctx, BinaryName, args...)

	// Setup stdout and stderr pipes
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return stream.Error(fmt.Errorf("failed to create stdout pipe: %w", err), true)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return stream.Error(fmt.Errorf("failed to create stderr pipe: %w", err), true)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return stream.Error(fmt.Errorf("failed to start nmap: %w", err), true)
	}

	// Buffer for collecting stdout (XML output)
	var stdoutBuf bytes.Buffer
	var stdoutMu sync.Mutex

	// Parse progress from stderr in goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()

			// Try to parse progress percentage
			if matches := progressRegex.FindStringSubmatch(line); len(matches) > 1 {
				if pct, err := strconv.ParseFloat(matches[1], 64); err == nil {
					// Round to integer percentage
					pctInt := int(pct)
					if pctInt > 100 {
						pctInt = 100
					}
					// Emit progress update (ignore errors to not interrupt scanning)
					stream.Progress(pctInt, "scanning", line)
				}
			}
		}
		if err := scanner.Err(); err != nil {
			stream.Warning(fmt.Sprintf("error reading stderr: %v", err), "stderr_scan")
		}
	}()

	// Read stdout in goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Buffer stdout for XML parsing
		stdoutMu.Lock()
		defer stdoutMu.Unlock()
		if _, err := io.Copy(&stdoutBuf, stdout); err != nil {
			stream.Warning(fmt.Sprintf("error reading stdout: %v", err), "stdout_read")
		}
	}()

	// Handle cancellation in goroutine
	cancelDone := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(cancelDone)

		select {
		case <-stream.Cancelled():
			// User requested cancellation
			stream.Warning("Scan cancellation requested", "cancellation")

			// Send SIGINT (Ctrl+C) to allow nmap to flush output gracefully
			if cmd.Process != nil {
				if err := cmd.Process.Signal(os.Interrupt); err != nil {
					stream.Warning(fmt.Sprintf("failed to send interrupt signal: %v", err), "cancellation")
				}
			}

		case <-ctx.Done():
			// Context cancelled (timeout or parent cancellation)
			stream.Warning(fmt.Sprintf("Context cancelled: %v", ctx.Err()), "context_cancel")

			// Send SIGINT for graceful shutdown
			if cmd.Process != nil {
				cmd.Process.Signal(os.Interrupt)
			}
		}
	}()

	// Wait for command to complete
	cmdErr := cmd.Wait()

	// Wait for all goroutines to finish
	wg.Wait()

	// Get the XML output
	stdoutMu.Lock()
	xmlOutput := stdoutBuf.Bytes()
	stdoutMu.Unlock()

	// Emit parsing progress
	if err := stream.Progress(90, "parsing", "Parsing nmap output"); err != nil {
		// Continue even if progress emission fails
	}

	// Parse output even if command errored (might have partial results)
	discoveryResult, parseErr := parseOutput(xmlOutput)

	// Handle different error scenarios
	if parseErr != nil {
		if cmdErr != nil {
			// Both command and parsing failed
			select {
			case <-stream.Cancelled():
				// Cancellation was requested - this is expected
				return stream.Error(fmt.Errorf("scan cancelled: %v", cmdErr), true)
			default:
				// Unexpected failure
				return stream.Error(fmt.Errorf("command failed: %v, parse failed: %v", cmdErr, parseErr), true)
			}
		}
		// Command succeeded but parsing failed (unusual)
		return stream.Error(fmt.Errorf("failed to parse nmap output: %w", parseErr), true)
	}

	// If command errored but we got partial results, emit warning
	if cmdErr != nil {
		select {
		case <-stream.Cancelled():
			stream.Warning("Scan cancelled, returning partial results", "cancellation")
		default:
			stream.Warning(fmt.Sprintf("Command exited with error: %v, but partial results available", cmdErr), "command_error")
		}
	}

	// Build response (reuse existing conversion function)
	scanDuration := time.Since(startTime).Seconds()
	response := convertToProtoResponse(discoveryResult, scanDuration, startTime)

	// Emit final progress
	if err := stream.Progress(100, "complete", "Scan finished"); err != nil {
		// Continue even if progress emission fails
	}

	// Complete the stream with final result
	return stream.Complete(response)
}
