// nmap-worker runs the nmap tool as a queue worker.
//
// This worker connects to Redis, pops nmap scan jobs from a queue,
// executes them, and publishes results back to Redis for consumption
// by the Gibson framework.
//
// Usage:
//
//	nmap-worker [flags]
//
// Flags:
//
//	-redis-url string
//	    Redis connection URL (default: REDIS_URL env or redis://localhost:6379)
//	-concurrency int
//	    Number of concurrent worker goroutines (default: 4)
//	-shutdown-timeout duration
//	    Time to wait for graceful shutdown (default: 30s)
//
// Environment Variables:
//
//	REDIS_URL       Redis connection URL (overridden by -redis-url flag)
//	LOG_LEVEL       Log level: debug, info, warn, error (default: info)
//
// Example:
//
//	# Start worker with default settings
//	nmap-worker
//
//	# Start worker with custom Redis URL and concurrency
//	nmap-worker -redis-url redis://redis.example.com:6379 -concurrency 8
//
//	# Start worker with environment variable
//	REDIS_URL=redis://localhost:6379 nmap-worker
//
// Signals:
//
//	SIGTERM, SIGINT   Initiate graceful shutdown
//
// The worker will:
//   - Register the nmap tool with Redis on startup
//   - Increment the worker count for load balancing
//   - Send periodic heartbeats to maintain health status
//   - Process work items from the tool:nmap:queue
//   - Publish results to job-specific result channels
//   - Decrement worker count and clean up on exit
//
// Architecture:
//
//	Redis Queue → Worker Pool → Tool Execution → Result Publishing
//	     ↓             ↓               ↓                ↓
//	  Pop Item    Unmarshal      nmap binary      Marshal JSON
//	              Proto Input                       Proto Output
//
// Note: This worker imports the tool implementation from the parent directory.
// Since the parent directory is package main, we need to build the worker with:
//
//	go build -o nmap-worker ./cmd/worker ./tool.go ./capabilities.go ./streaming.go
//
// Or use a proper package structure by refactoring nmap to use package nmap.
package main

import (
	"flag"
	"log"
	"log/slog"
	"os"

	"github.com/zero-day-ai/sdk/tool/worker"
)

func main() {
	// Parse CLI flags
	// When concurrency/shutdown-timeout are 0, worker.Run will use component.yaml defaults
	redisURL := flag.String("redis-url", os.Getenv("REDIS_URL"), "Redis URL (default: REDIS_URL env or redis://localhost:6379)")
	concurrency := flag.Int("concurrency", 0, "Number of concurrent workers (default: from component.yaml or 4)")
	shutdownTimeout := flag.Duration("shutdown-timeout", 0, "Time to wait for graceful shutdown (default: from component.yaml or 30s)")
	logLevel := flag.String("log-level", os.Getenv("LOG_LEVEL"), "Log level: debug, info, warn, error (default: info)")
	flag.Parse()

	// Parse log level
	level := slog.LevelInfo
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	// Create structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))

	// Create tool instance
	// NewTool() is defined in ../../tool.go (package main)
	// This will be available when we build with both files
	tool := NewTool()

	// Configure worker options
	// Zero values for Concurrency/ShutdownTimeout mean "use component.yaml defaults"
	opts := worker.Options{
		RedisURL:        *redisURL,
		Concurrency:     *concurrency,
		ShutdownTimeout: *shutdownTimeout,
		Logger:          logger,
	}

	logger.Info("starting nmap worker",
		"redis_url", opts.RedisURL,
		"concurrency", opts.Concurrency,
		"shutdown_timeout", opts.ShutdownTimeout,
	)

	// Run worker (blocks until shutdown)
	// worker.Run will load component.yaml from current directory and apply defaults
	if err := worker.Run(tool, opts); err != nil {
		log.Fatalf("Worker failed: %v", err)
	}
}
