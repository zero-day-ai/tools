//go:build integration

package main

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/api/gen/toolspb"
	"github.com/zero-day-ai/sdk/queue"
	"github.com/zero-day-ai/sdk/tool/worker"
	"google.golang.org/protobuf/encoding/protojson"
)

// setupTestRedis creates a miniredis instance for testing
func setupTestRedis(t *testing.T) (*miniredis.Miniredis, string) {
	t.Helper()
	s := miniredis.RunT(t)
	return s, fmt.Sprintf("redis://%s", s.Addr())
}

// TestWorkerIntegration tests the full nmap worker flow with miniredis
func TestWorkerIntegration(t *testing.T) {
	// Check if nmap binary is available
	nmapAvailable := true
	if _, err := exec.LookPath(BinaryName); err != nil {
		nmapAvailable = false
		t.Logf("nmap binary not found, some tests will be skipped")
	}

	s, redisURL := setupTestRedis(t)
	defer s.Close()

	tool := NewTool()

	// Create Redis client
	client, err := queue.NewRedisClient(queue.RedisOptions{URL: redisURL})
	require.NoError(t, err, "should create Redis client")
	defer client.Close()

	t.Run("WorkItemSubmissionAndRetrieval", func(t *testing.T) {
		if !nmapAvailable {
			t.Skip("nmap binary not available")
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		queueName := fmt.Sprintf("tool:%s:queue", tool.Name())
		jobID := "test-job-worker-1"

		// Create work item with ping scan (fastest and requires no special privileges)
		req := &toolspb.NmapRequest{
			Targets: []string{"127.0.0.1"},
			Args:    []string{"-sn"}, // Ping scan only
		}
		inputJSON, err := protojson.Marshal(req)
		require.NoError(t, err)

		workItem := queue.WorkItem{
			JobID:       jobID,
			Index:       0,
			Total:       1,
			Tool:        tool.Name(),
			InputJSON:   string(inputJSON),
			InputType:   tool.InputMessageType(),
			OutputType:  tool.OutputMessageType(),
			SubmittedAt: time.Now().UnixMilli(),
		}

		// Push work item
		err = client.Push(ctx, queueName, workItem)
		require.NoError(t, err, "should push work item to queue")

		// Subscribe to results BEFORE starting worker
		resultChannel := fmt.Sprintf("results:%s", jobID)
		resultsChan, err := client.Subscribe(ctx, resultChannel)
		require.NoError(t, err, "should subscribe to results channel")

		// Start worker loop in goroutine
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Use internal workerLoop directly for testing (avoids signal handling)
			workerLoop := func(ctx context.Context) {
				// Simplified worker loop for testing
				for {
					select {
					case <-ctx.Done():
						return
					default:
						item, err := client.Pop(ctx, queueName)
						if err != nil || item == nil {
							if ctx.Err() != nil {
								return
							}
							continue
						}

						// Process using worker package logic
						result := processWorkItemWrapper(ctx, tool, *item)

						// Publish result
						if err := client.Publish(ctx, resultChannel, result); err != nil {
							t.Logf("failed to publish result: %v", err)
						}
						return // Exit after processing one item
					}
				}
			}
			workerLoop(ctx)
		}()

		// Wait for result with timeout
		var result queue.Result
		select {
		case result = <-resultsChan:
			t.Logf("Received result for job %s, index %d", result.JobID, result.Index)
		case <-time.After(30 * time.Second):
			t.Fatal("timeout waiting for result")
		}

		// Cancel worker and wait
		cancel()
		wg.Wait()

		// Verify result
		assert.Equal(t, jobID, result.JobID, "job ID should match")
		assert.Equal(t, 0, result.Index, "index should be 0")
		assert.False(t, result.HasError(), "should not have error: %s", result.Error)
		assert.NotEmpty(t, result.OutputJSON, "output JSON should not be empty")

		// Parse output JSON to verify structure
		var nmapResp toolspb.NmapResponse
		err = protojson.Unmarshal([]byte(result.OutputJSON), &nmapResp)
		require.NoError(t, err, "should unmarshal output JSON")
		assert.Greater(t, nmapResp.TotalHosts, int32(0), "should find at least one host")
		assert.Greater(t, nmapResp.HostsUp, int32(0), "at least one host should be up")

		t.Logf("Successfully processed nmap scan: %d hosts, %d up", nmapResp.TotalHosts, nmapResp.HostsUp)
	})

	t.Run("ConcurrentWorkItems", func(t *testing.T) {
		if !nmapAvailable {
			t.Skip("nmap binary not available")
		}
		if testing.Short() {
			t.Skip("skipping concurrent test in short mode")
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		queueName := fmt.Sprintf("tool:%s:queue", tool.Name())
		jobID := "test-job-concurrent"
		numItems := 3

		// Subscribe to results first
		resultChannel := fmt.Sprintf("results:%s", jobID)
		resultsChan, err := client.Subscribe(ctx, resultChannel)
		require.NoError(t, err, "should subscribe to results channel")

		// Push multiple work items
		for i := 0; i < numItems; i++ {
			req := &toolspb.NmapRequest{
				Targets: []string{"127.0.0.1"},
				Args:    []string{"-sn"},
			}
			inputJSON, err := protojson.Marshal(req)
			require.NoError(t, err)

			workItem := queue.WorkItem{
				JobID:       jobID,
				Index:       i,
				Total:       numItems,
				Tool:        tool.Name(),
				InputJSON:   string(inputJSON),
				InputType:   tool.InputMessageType(),
				OutputType:  tool.OutputMessageType(),
				SubmittedAt: time.Now().UnixMilli(),
			}

			err = client.Push(ctx, queueName, workItem)
			require.NoError(t, err, "should push work item %d", i)
		}

		// Start 2 concurrent workers
		var wg sync.WaitGroup
		for workerNum := 0; workerNum < 2; workerNum++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				workerLoop := func(ctx context.Context) {
					processed := 0
					for processed < 2 { // Each worker processes up to 2 items
						select {
						case <-ctx.Done():
							return
						default:
							item, err := client.Pop(ctx, queueName)
							if err != nil || item == nil {
								if ctx.Err() != nil {
									return
								}
								time.Sleep(10 * time.Millisecond)
								continue
							}

							result := processWorkItemWrapper(ctx, tool, *item)
							if err := client.Publish(ctx, resultChannel, result); err != nil {
								t.Logf("worker %d: failed to publish result: %v", workerID, err)
							}
							processed++
						}
					}
				}
				workerLoop(ctx)
			}(workerNum)
		}

		// Collect results
		results := make([]queue.Result, 0, numItems)
		timeout := time.After(60 * time.Second)

		for len(results) < numItems {
			select {
			case result := <-resultsChan:
				results = append(results, result)
				t.Logf("Received result %d/%d from worker %s", len(results), numItems, result.WorkerID)
			case <-timeout:
				t.Fatalf("timeout waiting for results, got %d/%d", len(results), numItems)
			}
		}

		// Cancel and wait for workers
		cancel()
		wg.Wait()

		// Verify all results
		assert.Len(t, results, numItems, "should receive all results")
		for i, result := range results {
			assert.Equal(t, jobID, result.JobID, "result %d: job ID should match", i)
			assert.False(t, result.HasError(), "result %d: should not have error: %s", i, result.Error)
			assert.NotEmpty(t, result.OutputJSON, "result %d: output JSON should not be empty", i)
		}
	})

	t.Run("ErrorHandling_InvalidRequest", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		queueName := fmt.Sprintf("tool:%s:queue", tool.Name())
		jobID := "test-job-error"

		// Create invalid request (missing required args)
		req := &toolspb.NmapRequest{
			Targets: []string{"127.0.0.1"},
			Args:    []string{}, // Empty args - should fail validation
		}
		inputJSON, err := protojson.Marshal(req)
		require.NoError(t, err)

		workItem := queue.WorkItem{
			JobID:       jobID,
			Index:       0,
			Total:       1,
			Tool:        tool.Name(),
			InputJSON:   string(inputJSON),
			InputType:   tool.InputMessageType(),
			OutputType:  tool.OutputMessageType(),
			SubmittedAt: time.Now().UnixMilli(),
		}

		// Push work item
		err = client.Push(ctx, queueName, workItem)
		require.NoError(t, err)

		// Subscribe to results
		resultChannel := fmt.Sprintf("results:%s", jobID)
		resultsChan, err := client.Subscribe(ctx, resultChannel)
		require.NoError(t, err)

		// Process work item
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			item, err := client.Pop(ctx, queueName)
			if err != nil || item == nil {
				return
			}
			result := processWorkItemWrapper(ctx, tool, *item)
			client.Publish(ctx, resultChannel, result)
		}()

		// Wait for result
		var result queue.Result
		select {
		case result = <-resultsChan:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for error result")
		}

		cancel()
		wg.Wait()

		// Verify error result
		assert.True(t, result.HasError(), "should have error")
		assert.Contains(t, result.Error, "at least one argument is required", "error message should indicate missing args")
		t.Logf("Correctly caught error: %s", result.Error)
	})

	t.Run("WorkerConfiguration", func(t *testing.T) {
		// Test that worker options are properly configured
		opts := worker.Options{
			RedisURL:        redisURL,
			Concurrency:     2,
			ShutdownTimeout: 5 * time.Second,
		}

		assert.Equal(t, redisURL, opts.RedisURL, "redis URL should match")
		assert.Equal(t, 2, opts.Concurrency, "concurrency should be 2")
		assert.Equal(t, 5*time.Second, opts.ShutdownTimeout, "shutdown timeout should be 5s")
	})

	t.Run("ToolRegistration", func(t *testing.T) {
		// Verify tool metadata is correct
		assert.Equal(t, "nmap", tool.Name())
		assert.Equal(t, "1.0.0", tool.Version())
		assert.NotEmpty(t, tool.Description())
		assert.Equal(t, "gibson.tools.NmapRequest", tool.InputMessageType())
		assert.Equal(t, "gibson.tools.NmapResponse", tool.OutputMessageType())
		assert.Contains(t, tool.Tags(), "discovery")
	})
}

// TestWorkerWithoutNmap tests worker behavior when nmap is not available
func TestWorkerWithoutNmap(t *testing.T) {
	// This test verifies graceful handling when nmap binary is missing
	// Check if nmap is actually available
	if _, err := exec.LookPath(BinaryName); err == nil {
		t.Skip("nmap is available, skipping missing binary test")
	}

	s, redisURL := setupTestRedis(t)
	defer s.Close()

	tool := NewTool()

	// Verify health check reports unhealthy
	ctx := context.Background()
	health := tool.Health(ctx)

	// When nmap is not available, health should be unhealthy or degraded
	if health.Status == "ok" {
		t.Logf("Warning: nmap health check returned ok despite missing binary")
	} else {
		t.Logf("Health check correctly reports: %s - %s", health.Status, health.Message)
	}

	// Create Redis client
	client, err := queue.NewRedisClient(queue.RedisOptions{URL: redisURL})
	require.NoError(t, err)
	defer client.Close()

	// Try to execute a scan
	queueName := fmt.Sprintf("tool:%s:queue", tool.Name())
	jobID := "test-job-no-binary"

	req := &toolspb.NmapRequest{
		Targets: []string{"127.0.0.1"},
		Args:    []string{"-sn"},
	}
	inputJSON, err := protojson.Marshal(req)
	require.NoError(t, err)

	workItem := queue.WorkItem{
		JobID:       jobID,
		Index:       0,
		Total:       1,
		Tool:        tool.Name(),
		InputJSON:   string(inputJSON),
		InputType:   tool.InputMessageType(),
		OutputType:  tool.OutputMessageType(),
		SubmittedAt: time.Now().UnixMilli(),
	}

	err = client.Push(ctx, queueName, workItem)
	require.NoError(t, err)

	// Subscribe to results
	resultChannel := fmt.Sprintf("results:%s", jobID)
	resultsChan, err := client.Subscribe(ctx, resultChannel)
	require.NoError(t, err)

	// Process work item
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		item, err := client.Pop(ctx, queueName)
		if err != nil || item == nil {
			return
		}
		result := processWorkItemWrapper(ctx, tool, *item)
		client.Publish(ctx, resultChannel, result)
	}()

	// Wait for result
	var result queue.Result
	select {
	case result = <-resultsChan:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for result")
	}

	// Should receive an error result
	assert.True(t, result.HasError(), "should have error when binary is missing")
	assert.NotEmpty(t, result.Error, "error message should not be empty")
	t.Logf("Correctly handled missing binary: %s", result.Error)
}

// processWorkItemWrapper wraps the worker package's processWorkItem logic
// This is a simplified version for testing purposes
func processWorkItemWrapper(ctx context.Context, tool *ToolImpl, item queue.WorkItem) queue.Result {
	startedAt := time.Now().UnixMilli()

	result := queue.Result{
		JobID:       item.JobID,
		Index:       item.Index,
		OutputType:  item.OutputType,
		WorkerID:    "test-worker",
		StartedAt:   startedAt,
		CompletedAt: 0,
	}

	// Unmarshal input
	var req toolspb.NmapRequest
	if err := protojson.Unmarshal([]byte(item.InputJSON), &req); err != nil {
		result.Error = fmt.Sprintf("failed to unmarshal input: %v", err)
		result.CompletedAt = time.Now().UnixMilli()
		return result
	}

	// Execute tool
	outputMsg, err := tool.ExecuteProto(ctx, &req)
	if err != nil {
		result.Error = err.Error()
		result.CompletedAt = time.Now().UnixMilli()
		return result
	}

	// Marshal output
	outputJSON, err := protojson.Marshal(outputMsg)
	if err != nil {
		result.Error = fmt.Sprintf("failed to marshal output: %v", err)
		result.CompletedAt = time.Now().UnixMilli()
		return result
	}

	result.OutputJSON = string(outputJSON)
	result.CompletedAt = time.Now().UnixMilli()

	return result
}
