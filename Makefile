# Makefile for Gibson Tools Ecosystem
# Build, test, and manage all security tools organized by MITRE ATT&CK phases

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOWORK=$(GOCMD) work

# Build parameters
BIN_DIR=bin
BUILD_FLAGS=
VERBOSE_FLAG=

# Tool directories - organized by MITRE ATT&CK phase
# Reconnaissance Tools (TA0043)
RECON_TOOLS := \
	reconnaissance/subfinder \
	reconnaissance/httpx \
	reconnaissance/amass \
	reconnaissance/theharvester \
	reconnaissance/nuclei \
	reconnaissance/playwright \
	reconnaissance/recon-ng \
	reconnaissance/shodan \
	reconnaissance/spiderfoot

# Resource Development Tools (TA0042)
RESOURCE_DEV_TOOLS := \
	resource-development/searchsploit

# Initial Access Tools (TA0001)
INITIAL_ACCESS_TOOLS := \
	initial-access/sqlmap \
	initial-access/gobuster \
	initial-access/hydra \
	initial-access/metasploit

# Execution Tools (TA0002)
EXECUTION_TOOLS := \
	execution/evil-winrm \
	execution/impacket

# Persistence Tools (TA0003)
PERSISTENCE_TOOLS := \
	persistence/chisel

# Privilege Escalation Tools (TA0004)
PRIVESC_TOOLS := \
	privilege-escalation/linpeas \
	privilege-escalation/winpeas \
	privilege-escalation/john

# Defense Evasion Tools (TA0005)
DEFENSE_EVASION_TOOLS := \
	defense-evasion/msfvenom

# Credential Access Tools (TA0006)
CREDENTIAL_ACCESS_TOOLS := \
	credential-access/secretsdump

# Discovery Tools (TA0007)
DISCOVERY_TOOLS := \
	discovery/nmap \
	discovery/ping \
	discovery/bloodhound

# Lateral Movement Tools (TA0008)
LATERAL_MOVEMENT_TOOLS :=

# Collection Tools (TA0009)
COLLECTION_TOOLS :=

# Command and Control Tools (TA0011)
C2_TOOLS :=

# Exfiltration Tools (TA0010)
EXFILTRATION_TOOLS :=

# Impact Tools (TA0040)
IMPACT_TOOLS :=

# All tools combined
ALL_TOOLS := \
	$(RECON_TOOLS) \
	$(RESOURCE_DEV_TOOLS) \
	$(INITIAL_ACCESS_TOOLS) \
	$(EXECUTION_TOOLS) \
	$(PERSISTENCE_TOOLS) \
	$(PRIVESC_TOOLS) \
	$(DEFENSE_EVASION_TOOLS) \
	$(CREDENTIAL_ACCESS_TOOLS) \
	$(DISCOVERY_TOOLS) \
	$(LATERAL_MOVEMENT_TOOLS) \
	$(COLLECTION_TOOLS) \
	$(C2_TOOLS) \
	$(EXFILTRATION_TOOLS) \
	$(IMPACT_TOOLS)

# Binary names (extract basename from paths)
BINARIES := $(foreach tool,$(ALL_TOOLS),$(BIN_DIR)/$(notdir $(tool)))

# Default target
.DEFAULT_GOAL := all

# Phony targets
.PHONY: all build test integration-test clean help \
	build-recon build-resource-dev build-initial-access build-execution \
	build-persistence build-privesc build-defense-evasion build-credential-access \
	build-discovery build-lateral-movement build-collection build-c2 \
	build-exfiltration build-impact \
	verify deps tidy fmt vet lint

# Help target - display available targets
help:
	@echo "Gibson Tools Ecosystem - Build System"
	@echo "======================================"
	@echo ""
	@echo "Available targets:"
	@echo "  all              - Build and test all tools (default)"
	@echo "  build            - Build all tools to bin/ directory"
	@echo "  test             - Run all unit tests"
	@echo "  integration-test - Run integration tests (requires binaries installed)"
	@echo "  clean            - Remove all build artifacts"
	@echo "  verify           - Verify dependencies and run tests"
	@echo "  deps             - Download and verify dependencies"
	@echo "  tidy             - Tidy go modules"
	@echo "  fmt              - Format all Go code"
	@echo "  vet              - Run go vet on all packages"
	@echo "  lint             - Run golangci-lint (if available)"
	@echo ""
	@echo "Phase-specific build targets:"
	@echo "  build-recon              - Build reconnaissance tools"
	@echo "  build-resource-dev       - Build resource development tools"
	@echo "  build-initial-access     - Build initial access tools"
	@echo "  build-execution          - Build execution tools"
	@echo "  build-persistence        - Build persistence tools"
	@echo "  build-privesc            - Build privilege escalation tools"
	@echo "  build-defense-evasion    - Build defense evasion tools"
	@echo "  build-credential-access  - Build credential access tools"
	@echo "  build-discovery          - Build discovery tools"
	@echo "  build-lateral-movement   - Build lateral movement tools"
	@echo "  build-collection         - Build collection tools"
	@echo "  build-c2                 - Build command and control tools"
	@echo "  build-exfiltration       - Build exfiltration tools"
	@echo "  build-impact             - Build impact tools"
	@echo ""
	@echo "Examples:"
	@echo "  make              # Build and test all tools"
	@echo "  make build        # Build all tools"
	@echo "  make test         # Run unit tests"
	@echo "  make clean        # Clean build artifacts"
	@echo "  make build-recon  # Build only reconnaissance tools"

# All target - build and test
all: build test

# Build all tools
build: $(BIN_DIR)
	@echo "Building all Gibson Tools..."
	@$(MAKE) --no-print-directory $(BINARIES)
	@echo "Build complete! Binaries are in $(BIN_DIR)/"

# Create bin directory
$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Generic build rule for individual tools
$(BIN_DIR)/%: */% | $(BIN_DIR)
	@tool_path=$$(find . -type d -name "$*" | head -1); \
	if [ -z "$$tool_path" ]; then \
		echo "Error: Could not find tool $*"; \
		exit 1; \
	fi; \
	if [ ! -f "$$tool_path/main.go" ]; then \
		echo "Warning: No main.go found in $$tool_path, skipping"; \
		exit 0; \
	fi; \
	echo "Building $*..."; \
	cd $$tool_path && $(GOBUILD) $(BUILD_FLAGS) -o ../../$(BIN_DIR)/$* . && \
	echo "  ✓ Built $* ($$(du -h ../../$(BIN_DIR)/$* | cut -f1))"

# Phase-specific build targets
build-recon: $(BIN_DIR)
	@echo "Building Reconnaissance tools..."
	@$(foreach tool,$(RECON_TOOLS),$(MAKE) --no-print-directory $(BIN_DIR)/$(notdir $(tool));)

build-resource-dev: $(BIN_DIR)
	@echo "Building Resource Development tools..."
	@$(foreach tool,$(RESOURCE_DEV_TOOLS),$(MAKE) --no-print-directory $(BIN_DIR)/$(notdir $(tool));)

build-initial-access: $(BIN_DIR)
	@echo "Building Initial Access tools..."
	@$(foreach tool,$(INITIAL_ACCESS_TOOLS),$(MAKE) --no-print-directory $(BIN_DIR)/$(notdir $(tool));)

build-execution: $(BIN_DIR)
	@echo "Building Execution tools..."
	@$(foreach tool,$(EXECUTION_TOOLS),$(MAKE) --no-print-directory $(BIN_DIR)/$(notdir $(tool));)

build-persistence: $(BIN_DIR)
	@echo "Building Persistence tools..."
	@$(foreach tool,$(PERSISTENCE_TOOLS),$(MAKE) --no-print-directory $(BIN_DIR)/$(notdir $(tool));)

build-privesc: $(BIN_DIR)
	@echo "Building Privilege Escalation tools..."
	@$(foreach tool,$(PRIVESC_TOOLS),$(MAKE) --no-print-directory $(BIN_DIR)/$(notdir $(tool));)

build-defense-evasion: $(BIN_DIR)
	@echo "Building Defense Evasion tools..."
	@$(foreach tool,$(DEFENSE_EVASION_TOOLS),$(MAKE) --no-print-directory $(BIN_DIR)/$(notdir $(tool));)

build-credential-access: $(BIN_DIR)
	@echo "Building Credential Access tools..."
	@$(foreach tool,$(CREDENTIAL_ACCESS_TOOLS),$(MAKE) --no-print-directory $(BIN_DIR)/$(notdir $(tool));)

build-discovery: $(BIN_DIR)
	@echo "Building Discovery tools..."
	@$(foreach tool,$(DISCOVERY_TOOLS),$(MAKE) --no-print-directory $(BIN_DIR)/$(notdir $(tool));)

build-lateral-movement: $(BIN_DIR)
	@echo "Building Lateral Movement tools..."
	@$(foreach tool,$(LATERAL_MOVEMENT_TOOLS),$(MAKE) --no-print-directory $(BIN_DIR)/$(notdir $(tool));)

build-collection: $(BIN_DIR)
	@echo "Building Collection tools..."
	@$(foreach tool,$(COLLECTION_TOOLS),$(MAKE) --no-print-directory $(BIN_DIR)/$(notdir $(tool));)

build-c2: $(BIN_DIR)
	@echo "Building Command and Control tools..."
	@$(foreach tool,$(C2_TOOLS),$(MAKE) --no-print-directory $(BIN_DIR)/$(notdir $(tool));)

build-exfiltration: $(BIN_DIR)
	@echo "Building Exfiltration tools..."
	@$(foreach tool,$(EXFILTRATION_TOOLS),$(MAKE) --no-print-directory $(BIN_DIR)/$(notdir $(tool));)

build-impact: $(BIN_DIR)
	@echo "Building Impact tools..."
	@$(foreach tool,$(IMPACT_TOOLS),$(MAKE) --no-print-directory $(BIN_DIR)/$(notdir $(tool));)

# Run all unit tests
test:
	@echo "Running unit tests..."
	@if [ -d "pkg" ] && [ -f "pkg/go.mod" ]; then \
		echo "Testing pkg..."; \
		cd pkg && $(GOTEST) -v ./... && cd - > /dev/null || exit 1; \
	fi
	@for dir in $(ALL_TOOLS); do \
		if [ -d "$$dir" ] && [ -f "$$dir/go.mod" ]; then \
			echo "Testing $$dir..."; \
			cd $$dir && $(GOTEST) -v . && cd - > /dev/null || exit 1; \
		fi; \
	done
	@echo "All tests passed!"

# Run integration tests (requires actual binaries installed)
integration-test:
	@echo "Running integration tests..."
	@echo "Note: Integration tests require actual security tools to be installed"
	@if [ -d "pkg" ] && [ -f "pkg/go.mod" ]; then \
		echo "Integration testing pkg..."; \
		cd pkg && $(GOTEST) -v -tags=integration ./... && cd - > /dev/null || exit 1; \
	fi
	@for dir in $(ALL_TOOLS); do \
		if [ -d "$$dir" ] && [ -f "$$dir/go.mod" ]; then \
			echo "Integration testing $$dir..."; \
			cd $$dir && $(GOTEST) -v -tags=integration . && cd - > /dev/null || exit 1; \
		fi; \
	done
	@echo "All integration tests passed!"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BIN_DIR)
	@$(GOCLEAN) -cache
	@echo "Clean complete!"

# Verify dependencies and run tests
verify: deps test
	@echo "Verification complete!"

# Download and verify dependencies
deps:
	@echo "Downloading dependencies..."
	@$(GOWORK) sync
	@echo "Dependencies downloaded!"

# Tidy go modules
tidy:
	@echo "Tidying modules..."
	@for dir in pkg $(ALL_TOOLS); do \
		if [ -f "$$dir/go.mod" ]; then \
			echo "  Tidying $$dir..."; \
			cd $$dir && $(GOMOD) tidy && cd - > /dev/null; \
		fi; \
	done
	@echo "Modules tidied!"

# Format all Go code
fmt:
	@echo "Formatting Go code..."
	@gofmt -w -s .
	@echo "Code formatted!"

# Run go vet on all packages
vet:
	@echo "Running go vet..."
	@$(GOCMD) vet ./...
	@echo "Vet complete!"

# Run golangci-lint (if available)
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, skipping..."; \
		echo "Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Show build statistics
stats: build
	@echo ""
	@echo "Build Statistics"
	@echo "================"
	@echo "Total tools: $$(ls -1 $(BIN_DIR) | wc -l)"
	@echo "Total size: $$(du -sh $(BIN_DIR) | cut -f1)"
	@echo ""
	@echo "By phase:"
	@echo "  Reconnaissance: $(words $(RECON_TOOLS))"
	@echo "  Resource Development: $(words $(RESOURCE_DEV_TOOLS))"
	@echo "  Initial Access: $(words $(INITIAL_ACCESS_TOOLS))"
	@echo "  Execution: $(words $(EXECUTION_TOOLS))"
	@echo "  Persistence: $(words $(PERSISTENCE_TOOLS))"
	@echo "  Privilege Escalation: $(words $(PRIVESC_TOOLS))"
	@echo "  Defense Evasion: $(words $(DEFENSE_EVASION_TOOLS))"
	@echo "  Credential Access: $(words $(CREDENTIAL_ACCESS_TOOLS))"
	@echo "  Discovery: $(words $(DISCOVERY_TOOLS))"
	@echo ""
	@echo "Binaries:"
	@ls -lh $(BIN_DIR) | tail -n +2
