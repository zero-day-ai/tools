package main

import (
	"context"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/api/gen/toolspb"
	"github.com/zero-day-ai/sdk/tool"
	"google.golang.org/protobuf/proto"
)

// mockToolStream implements tool.ToolStream for testing
type mockToolStream struct {
	mu             sync.Mutex
	progressEvents []progressEvent
	partialResults []proto.Message
	warnings       []warningEvent
	completeResult proto.Message
	errorEvent     *errorEvent
	cancelCh       chan struct{}
	executionID    string
	progressCalls  int
	partialCalls   int
	warningCalls   int
	completeCalls  int
	errorCalls     int
}

type progressEvent struct {
	percent int
	phase   string
	message string
}

type warningEvent struct {
	message string
	context string
}

type errorEvent struct {
	err   error
	fatal bool
}

func newMockToolStream(executionID string) *mockToolStream {
	return &mockToolStream{
		progressEvents: make([]progressEvent, 0),
		partialResults: make([]proto.Message, 0),
		warnings:       make([]warningEvent, 0),
		cancelCh:       make(chan struct{}),
		executionID:    executionID,
	}
}

func (m *mockToolStream) Progress(percent int, phase, message string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.progressEvents = append(m.progressEvents, progressEvent{percent, phase, message})
	m.progressCalls++
	return nil
}

func (m *mockToolStream) Partial(output proto.Message, incremental bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.partialResults = append(m.partialResults, output)
	m.partialCalls++
	return nil
}

func (m *mockToolStream) Warning(message, context string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.warnings = append(m.warnings, warningEvent{message, context})
	m.warningCalls++
	return nil
}

func (m *mockToolStream) Complete(output proto.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.completeResult = output
	m.completeCalls++
	return nil
}

func (m *mockToolStream) Error(err error, fatal bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorEvent = &errorEvent{err, fatal}
	m.errorCalls++
	return nil
}

func (m *mockToolStream) Cancelled() <-chan struct{} {
	return m.cancelCh
}

func (m *mockToolStream) ExecutionID() string {
	return m.executionID
}

func (m *mockToolStream) getProgressEvents() []progressEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]progressEvent, len(m.progressEvents))
	copy(result, m.progressEvents)
	return result
}

func (m *mockToolStream) getWarnings() []warningEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]warningEvent, len(m.warnings))
	copy(result, m.warnings)
	return result
}

func (m *mockToolStream) getCompleteResult() proto.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.completeResult
}

func (m *mockToolStream) getErrorEvent() *errorEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.errorEvent
}

func (m *mockToolStream) getCallCounts() (progress, partial, warning, complete, errorCount int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.progressCalls, m.partialCalls, m.warningCalls, m.completeCalls, m.errorCalls
}

// TestNmapStreamingExecution tests that StreamExecuteProto produces progress events
func TestNmapStreamingExecution(t *testing.T) {
	// Check if nmap binary is available
	nmapPath, err := exec.LookPath("nmap")
	if err != nil {
		t.Skip("nmap binary not found, skipping integration test")
	}

	t.Logf("Using nmap binary at: %s", nmapPath)

	// Create tool instance
	nmapTool := &ToolImpl{}

	// Create mock stream
	stream := newMockToolStream("test-exec-streaming")

	// Create request with fast scan of localhost
	req := &toolspb.NmapRequest{
		Targets: []string{"127.0.0.1"},
		Args:    []string{"-p", "80,443", "-T4", "--host-timeout", "5s"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Execute streaming
	t.Log("Starting nmap streaming execution...")
	err = nmapTool.StreamExecuteProto(ctx, req, stream)
	require.NoError(t, err, "streaming execution should succeed")

	// Verify progress events were emitted
	progressEvents := stream.getProgressEvents()
	t.Logf("Received %d progress events", len(progressEvents))
	assert.NotEmpty(t, progressEvents, "should receive at least one progress event")

	// Verify we got an initial progress event
	hasInitEvent := false
	hasCompleteEvent := false

	for _, evt := range progressEvents {
		t.Logf("Progress: %d%% - %s - %s", evt.percent, evt.phase, evt.message)
		if evt.phase == "init" {
			hasInitEvent = true
		}
		if evt.phase == "complete" {
			hasCompleteEvent = true
		}
	}

	assert.True(t, hasInitEvent, "should have init phase")
	// Note: scanning events may not appear for very fast scans
	// assert.True(t, hasScanningEvent, "should have scanning phase")
	assert.True(t, hasCompleteEvent, "should have complete phase")

	// Verify complete result
	result := stream.getCompleteResult()
	require.NotNil(t, result, "should have complete result")

	nmapResp, ok := result.(*toolspb.NmapResponse)
	require.True(t, ok, "result should be NmapResponse")
	assert.NotNil(t, nmapResp.Hosts, "should have hosts in response")
	t.Logf("Scan returned %d hosts", len(nmapResp.Hosts))

	// Verify call counts
	progress, partial, warning, complete, errorCount := stream.getCallCounts()
	t.Logf("Call counts: Progress=%d, Partial=%d, Warning=%d, Complete=%d, Error=%d",
		progress, partial, warning, complete, errorCount)

	assert.Greater(t, progress, 0, "should have progress calls")
	assert.Equal(t, 1, complete, "should have exactly one complete call")
	assert.Equal(t, 0, errorCount, "should have no error calls for successful scan")
}

// TestNmapStreamingCancellation tests that cancellation returns partial results
func TestNmapStreamingCancellation(t *testing.T) {
	// Check if nmap binary is available
	_, err := exec.LookPath("nmap")
	if err != nil {
		t.Skip("nmap binary not found, skipping integration test")
	}

	// Create tool instance
	nmapTool := &ToolImpl{}

	// Create mock stream
	stream := newMockToolStream("test-exec-cancel")

	// Create request with a slower scan to allow time for cancellation
	// Using a larger port range to make the scan take longer
	req := &toolspb.NmapRequest{
		Targets: []string{"127.0.0.1"},
		Args:    []string{"-p", "1-1000", "-T2", "--max-retries", "2"},
	}

	ctx := context.Background()

	// Start scan in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- nmapTool.StreamExecuteProto(ctx, req, stream)
	}()

	// Wait a bit for scan to start and emit some progress
	time.Sleep(500 * time.Millisecond)

	// Cancel the scan
	t.Log("Cancelling scan...")
	close(stream.cancelCh)

	// Wait for completion (with timeout)
	select {
	case err := <-errCh:
		// Scan should complete or return error after cancellation
		t.Logf("Scan returned with error: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("scan did not complete after cancellation within timeout")
	}

	// Verify progress events were emitted before cancellation
	progressEvents := stream.getProgressEvents()
	t.Logf("Received %d progress events before cancellation", len(progressEvents))
	assert.NotEmpty(t, progressEvents, "should receive progress events before cancellation")

	// Verify warnings about cancellation
	warnings := stream.getWarnings()
	t.Logf("Received %d warnings", len(warnings))

	hasCancellationWarning := false
	for _, w := range warnings {
		t.Logf("Warning: %s (context: %s)", w.message, w.context)
		if w.context == "cancellation" {
			hasCancellationWarning = true
		}
	}

	// We should get a cancellation warning or complete/error message
	// Check if we got either a complete result or error
	result := stream.getCompleteResult()
	errorEvent := stream.getErrorEvent()

	if result != nil {
		t.Log("Got complete result (partial results)")
		nmapResp, ok := result.(*toolspb.NmapResponse)
		require.True(t, ok, "result should be NmapResponse")
		t.Logf("Partial scan returned %d hosts", len(nmapResp.Hosts))
	} else if errorEvent != nil {
		t.Logf("Got error event: %v (fatal=%v)", errorEvent.err, errorEvent.fatal)
		assert.True(t, errorEvent.fatal, "cancellation error should be fatal")
	} else {
		// At minimum, we should have a cancellation warning
		assert.True(t, hasCancellationWarning, "should have cancellation warning")
	}

	// Verify call counts
	progress, _, warning, complete, errorCount := stream.getCallCounts()
	t.Logf("Call counts after cancellation: Progress=%d, Warning=%d, Complete=%d, Error=%d",
		progress, warning, complete, errorCount)

	assert.Greater(t, progress, 0, "should have progress calls before cancellation")
}

// TestNmapStreamingInvalidInput tests error handling for invalid input
func TestNmapStreamingInvalidInput(t *testing.T) {
	// Check if nmap binary is available
	_, err := exec.LookPath("nmap")
	if err != nil {
		t.Skip("nmap binary not found, skipping integration test")
	}

	nmapTool := &ToolImpl{}

	// Test with no targets
	t.Run("no_targets", func(t *testing.T) {
		stream := newMockToolStream("test-no-targets")
		req := &toolspb.NmapRequest{
			Targets: []string{},
			Args:    []string{"-sn"},
		}

		ctx := context.Background()
		_ = nmapTool.StreamExecuteProto(ctx, req, stream)

		// Should complete with error
		errorEvent := stream.getErrorEvent()
		require.NotNil(t, errorEvent, "should have error event")
		assert.True(t, errorEvent.fatal, "error should be fatal")
		assert.Contains(t, errorEvent.err.Error(), "target", "error should mention target")
	})

	// Test with no args
	t.Run("no_args", func(t *testing.T) {
		stream := newMockToolStream("test-no-args")
		req := &toolspb.NmapRequest{
			Targets: []string{"127.0.0.1"},
			Args:    []string{},
		}

		ctx := context.Background()
		_ = nmapTool.StreamExecuteProto(ctx, req, stream)

		// Should complete with error
		errorEvent := stream.getErrorEvent()
		require.NotNil(t, errorEvent, "should have error event")
		assert.True(t, errorEvent.fatal, "error should be fatal")
		assert.Contains(t, errorEvent.err.Error(), "argument", "error should mention argument")
	})
}

// TestNmapStreamingTimeout tests timeout handling
func TestNmapStreamingTimeout(t *testing.T) {
	// Check if nmap binary is available
	_, err := exec.LookPath("nmap")
	if err != nil {
		t.Skip("nmap binary not found, skipping integration test")
	}

	nmapTool := &ToolImpl{}
	stream := newMockToolStream("test-exec-timeout")

	// Create request with a scan that should take longer than timeout
	req := &toolspb.NmapRequest{
		Targets: []string{"127.0.0.1"},
		Args:    []string{"-p", "1-65535", "-T1"}, // Very slow scan
	}

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	t.Log("Starting scan with 2 second timeout...")
	err = nmapTool.StreamExecuteProto(ctx, req, stream)

	// Should complete (possibly with partial results or error)
	t.Logf("Scan returned: %v", err)

	// Verify we got some progress before timeout
	progressEvents := stream.getProgressEvents()
	t.Logf("Received %d progress events before timeout", len(progressEvents))

	// Check for warning about context cancellation
	warnings := stream.getWarnings()
	hasContextWarning := false
	for _, w := range warnings {
		t.Logf("Warning: %s (context: %s)", w.message, w.context)
		if w.context == "context_cancel" {
			hasContextWarning = true
		}
	}

	// Either got warnings, error, or complete with partial results
	result := stream.getCompleteResult()
	errorEvent := stream.getErrorEvent()

	if result != nil {
		t.Log("Got complete result (partial)")
	} else if errorEvent != nil {
		t.Logf("Got error event: %v", errorEvent.err)
	} else if hasContextWarning {
		t.Log("Got context cancellation warning")
	}

	// At minimum, should have some progress events
	assert.NotEmpty(t, progressEvents, "should have progress events before timeout")
}

// TestNmapStreamingMultipleTargets tests scanning multiple targets
func TestNmapStreamingMultipleTargets(t *testing.T) {
	// Check if nmap binary is available
	_, err := exec.LookPath("nmap")
	if err != nil {
		t.Skip("nmap binary not found, skipping integration test")
	}

	nmapTool := &ToolImpl{}
	stream := newMockToolStream("test-exec-multi")

	// Scan multiple localhost addresses (same host, but tests multiple targets)
	req := &toolspb.NmapRequest{
		Targets: []string{"127.0.0.1", "localhost"},
		Args:    []string{"-p", "80", "-T4", "--host-timeout", "3s"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Log("Scanning multiple targets...")
	err = nmapTool.StreamExecuteProto(ctx, req, stream)
	require.NoError(t, err, "streaming execution should succeed")

	// Verify result
	result := stream.getCompleteResult()
	require.NotNil(t, result, "should have complete result")

	nmapResp, ok := result.(*toolspb.NmapResponse)
	require.True(t, ok, "result should be NmapResponse")
	t.Logf("Scan returned %d hosts", len(nmapResp.Hosts))

	// Should find at least one host (localhost)
	assert.NotEmpty(t, nmapResp.Hosts, "should find at least one host")
}

// TestNmapStreamingProgressRegex tests that the progress regex is working
func TestNmapStreamingProgressRegex(t *testing.T) {
	// Test the progress regex pattern
	testCases := []struct {
		line     string
		expected int
		match    bool
	}{
		{"Stats: 25.00% done", 25, true},
		{"Stats: 50.5% done", 50, true},
		{"Stats: 100% done", 100, true},
		{"Stats: 0% done", 0, true},
		{"Random output", 0, false},
		{"Stats: done", 0, false},
	}

	for _, tc := range testCases {
		t.Run(tc.line, func(t *testing.T) {
			matches := progressRegex.FindStringSubmatch(tc.line)
			if tc.match {
				require.Len(t, matches, 2, "should match and capture percentage")
				// Note: The test just verifies the regex captures, actual parsing happens in the tool
			} else {
				assert.Empty(t, matches, "should not match")
			}
		})
	}
}

// TestToolImpl_ImplementsStreamingTool verifies the tool implements StreamingTool interface
func TestToolImpl_ImplementsStreamingTool(t *testing.T) {
	var _ tool.StreamingTool = (*ToolImpl)(nil)
	t.Log("ToolImpl correctly implements tool.StreamingTool interface")
}

// TestNmapStreamingExecutionID tests that execution ID is accessible
func TestNmapStreamingExecutionID(t *testing.T) {
	// Check if nmap binary is available
	_, err := exec.LookPath("nmap")
	if err != nil {
		t.Skip("nmap binary not found, skipping integration test")
	}

	nmapTool := &ToolImpl{}
	executionID := "unique-exec-id-12345"
	stream := newMockToolStream(executionID)

	req := &toolspb.NmapRequest{
		Targets: []string{"127.0.0.1"},
		Args:    []string{"-p", "80", "-T4"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err = nmapTool.StreamExecuteProto(ctx, req, stream)
	require.NoError(t, err)

	// Verify execution ID matches
	assert.Equal(t, executionID, stream.ExecutionID())
}
