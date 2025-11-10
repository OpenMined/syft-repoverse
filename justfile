# Integration test commands for syftbox

# Directory paths
SYFTBOX_DIR := "./syftbox"
TEST_CLIENTS_DIR := "./sandbox"
DOCKER_DIR := SYFTBOX_DIR + "/docker"

# Test configuration
TEST_CLIENT1_EMAIL := "alice@syftbox.net"
TEST_CLIENT2_EMAIL := "bob@syftbox.net"
TEST_CLIENT1_NAME := "alice-syftbox-net"
TEST_CLIENT2_NAME := "bob-syftbox-net"
TEST_CLIENT1_PORT := "7938"
TEST_CLIENT2_PORT := "7939"

SYC_CLIENT_ALICE_EMAIL := "alice@syftbox.net"
SYC_CLIENT_BOB_EMAIL := "bob@syftbox.net"
SYC_CLIENT_CHARLIE_EMAIL := "charlie@syftbox.net"
SYC_CLIENT_ALICE_NAME := "alice-syftbox-net"
SYC_CLIENT_BOB_NAME := "bob-syftbox-net"
SYC_CLIENT_CHARLIE_NAME := "charlie-syftbox-net"
SYC_CLIENT_ALICE_PORT := "7940"
SYC_CLIENT_BOB_PORT := "7941"
SYC_CLIENT_CHARLIE_PORT := "7942"

# Default target
default:
    @just --list

# Set up test environment
setup:
    @echo "Setting up test environment..."
    -rm -rf {{TEST_CLIENTS_DIR}}
    @mkdir -p {{TEST_CLIENTS_DIR}}
    @echo "Test environment ready."

# Start the server with MinIO
start-server:
    @echo "Starting SyftBox server with MinIO..."
    cd {{DOCKER_DIR}} && COMPOSE_BAKE=true docker compose up -d --build minio server
    @echo "Waiting for server to be ready..."
    @sleep 5
    @echo "Server started at http://localhost:8080"

build-client-image:
    @echo "Building SyftBox client image..."
    @if [ -n "$${DOCKER_BUILDX:-}" ]; then \
        cd {{SYFTBOX_DIR}} && docker buildx build --cache-from=type=gha --cache-to=type=gha,mode=max -f docker/Dockerfile.client -t syftbox-client --load .; \
    else \
        cd {{SYFTBOX_DIR}} && docker build -f docker/Dockerfile.client -t syftbox-client .; \
    fi

# Start client 1
start-client1:
    @echo "Starting client Alice ({{TEST_CLIENT1_EMAIL}})..."
    @just build-client-image
    @echo "Starting Alice container..."
    @mkdir -p "$(pwd)/{{TEST_CLIENTS_DIR}}/{{TEST_CLIENT1_EMAIL}}/SyftBox"
    docker run -d \
        --name syftbox-client-{{TEST_CLIENT1_NAME}} \
        --network docker_syftbox-network \
        -p {{TEST_CLIENT1_PORT}}:7938 \
        -e SYFTBOX_SERVER_URL=http://syftbox-server:8080 \
        -e SYFTBOX_AUTH_ENABLED=0 \
        -v "$(pwd)/{{TEST_CLIENTS_DIR}}:/data/clients" \
        -v "$(pwd)/{{TEST_CLIENTS_DIR}}/{{TEST_CLIENT1_EMAIL}}/SyftBox:/root/SyftBox" \
        syftbox-client {{TEST_CLIENT1_EMAIL}}
    @echo "Client Alice started at http://localhost:{{TEST_CLIENT1_PORT}}"

# Start client 2
start-client2:
    @echo "Starting client Bob ({{TEST_CLIENT2_EMAIL}})..."
    @echo "Starting Bob container..."
    @mkdir -p "$(pwd)/{{TEST_CLIENTS_DIR}}/{{TEST_CLIENT2_EMAIL}}/SyftBox"
    docker run -d \
        --name syftbox-client-{{TEST_CLIENT2_NAME}} \
        --network docker_syftbox-network \
        -p {{TEST_CLIENT2_PORT}}:7938 \
        -e SYFTBOX_SERVER_URL=http://syftbox-server:8080 \
        -e SYFTBOX_AUTH_ENABLED=0 \
        -v "$(pwd)/{{TEST_CLIENTS_DIR}}:/data/clients" \
        -v "$(pwd)/{{TEST_CLIENTS_DIR}}/{{TEST_CLIENT2_EMAIL}}/SyftBox:/root/SyftBox" \
        syftbox-client {{TEST_CLIENT2_EMAIL}}
    @echo "Client Bob started at http://localhost:{{TEST_CLIENT2_PORT}}"

start-syc-alice:
    @echo "Starting Syft Crypto client Alice ({{SYC_CLIENT_ALICE_EMAIL}})..."
    @mkdir -p "$(pwd)/{{TEST_CLIENTS_DIR}}/{{SYC_CLIENT_ALICE_EMAIL}}/SyftBox"
    docker run -d \
        --name syftbox-client-{{SYC_CLIENT_ALICE_NAME}} \
        --network docker_syftbox-network \
        -p {{SYC_CLIENT_ALICE_PORT}}:7938 \
        -e SYFTBOX_SERVER_URL=http://syftbox-server:8080 \
        -e SYFTBOX_AUTH_ENABLED=0 \
        -v "$(pwd)/{{TEST_CLIENTS_DIR}}:/data/clients" \
        -v "$(pwd)/{{TEST_CLIENTS_DIR}}/{{SYC_CLIENT_ALICE_EMAIL}}/SyftBox:/root/SyftBox" \
        syftbox-client {{SYC_CLIENT_ALICE_EMAIL}}
    @echo "Alice client started at http://localhost:{{SYC_CLIENT_ALICE_PORT}}"

start-syc-bob:
    @echo "Starting Syft Crypto client Bob ({{SYC_CLIENT_BOB_EMAIL}})..."
    @mkdir -p "$(pwd)/{{TEST_CLIENTS_DIR}}/{{SYC_CLIENT_BOB_EMAIL}}/SyftBox"
    docker run -d \
        --name syftbox-client-{{SYC_CLIENT_BOB_NAME}} \
        --network docker_syftbox-network \
        -p {{SYC_CLIENT_BOB_PORT}}:7938 \
        -e SYFTBOX_SERVER_URL=http://syftbox-server:8080 \
        -e SYFTBOX_AUTH_ENABLED=0 \
        -v "$(pwd)/{{TEST_CLIENTS_DIR}}:/data/clients" \
        -v "$(pwd)/{{TEST_CLIENTS_DIR}}/{{SYC_CLIENT_BOB_EMAIL}}/SyftBox:/root/SyftBox" \
        syftbox-client {{SYC_CLIENT_BOB_EMAIL}}
    @echo "Bob client started at http://localhost:{{SYC_CLIENT_BOB_PORT}}"

start-syc-charlie:
    @echo "Starting Syft Crypto client Charlie ({{SYC_CLIENT_CHARLIE_EMAIL}})..."
    @mkdir -p "$(pwd)/{{TEST_CLIENTS_DIR}}/{{SYC_CLIENT_CHARLIE_EMAIL}}/SyftBox"
    docker run -d \
        --name syftbox-client-{{SYC_CLIENT_CHARLIE_NAME}} \
        --network docker_syftbox-network \
        -p {{SYC_CLIENT_CHARLIE_PORT}}:7938 \
        -e SYFTBOX_SERVER_URL=http://syftbox-server:8080 \
        -e SYFTBOX_AUTH_ENABLED=0 \
        -v "$(pwd)/{{TEST_CLIENTS_DIR}}:/data/clients" \
        -v "$(pwd)/{{TEST_CLIENTS_DIR}}/{{SYC_CLIENT_CHARLIE_EMAIL}}/SyftBox:/root/SyftBox" \
        syftbox-client {{SYC_CLIENT_CHARLIE_EMAIL}}
    @echo "Charlie client started at http://localhost:{{SYC_CLIENT_CHARLIE_PORT}}"

start-syc: setup start-server
    @sleep 3
    @just build-client-image
    @sleep 2
    @just start-syc-alice
    @sleep 2
    @just start-syc-bob
    @sleep 2
    @just start-syc-charlie
    @echo "Syft Crypto test environment started!"

# Start all services
start-all: setup start-server
    @sleep 3
    @just start-client1
    @sleep 2
    @just start-client2
    @sleep 2
    @just start-syc-charlie
    @echo "All services started!"

# Stop all services
stop-all:
    @echo "Stopping all services..."
    -docker stop syftbox-client-{{TEST_CLIENT1_NAME}}
    -docker stop syftbox-client-{{TEST_CLIENT2_NAME}}
    -docker stop syftbox-client-{{SYC_CLIENT_ALICE_NAME}}
    -docker stop syftbox-client-{{SYC_CLIENT_BOB_NAME}}
    -docker stop syftbox-client-{{SYC_CLIENT_CHARLIE_NAME}}
    -cd {{DOCKER_DIR}} && docker compose down
    @echo "All services stopped."

# Quick restart - reset clients and MinIO state without stopping server
quick-restart:
    @echo "Quick restart - resetting clients and storage..."
    # Stop and remove client containers
    -docker stop syftbox-client-{{TEST_CLIENT1_NAME}}
    -docker stop syftbox-client-{{TEST_CLIENT2_NAME}}
    -docker stop syftbox-client-{{SYC_CLIENT_ALICE_NAME}}
    -docker stop syftbox-client-{{SYC_CLIENT_BOB_NAME}}
    -docker stop syftbox-client-{{SYC_CLIENT_CHARLIE_NAME}}
    -docker rm syftbox-client-{{TEST_CLIENT1_NAME}}
    -docker rm syftbox-client-{{TEST_CLIENT2_NAME}}
    -docker rm syftbox-client-{{SYC_CLIENT_ALICE_NAME}}
    -docker rm syftbox-client-{{SYC_CLIENT_BOB_NAME}}
    -docker rm syftbox-client-{{SYC_CLIENT_CHARLIE_NAME}}
    # Remove client data
    -rm -rf {{TEST_CLIENTS_DIR}}
    # Reset MinIO data by recreating the volume
    -cd {{DOCKER_DIR}} && docker compose stop minio
    -cd {{DOCKER_DIR}} && docker compose rm -f minio
    -docker volume rm docker_minio-data || true
    # Restart MinIO and server
    -cd {{DOCKER_DIR}} && docker compose up -d --build minio server
    @echo "Waiting for server to be ready..."
    @sleep 5
    # Restart clients
    @just start-client1
    @sleep 2
    @just start-client2
    @echo "Quick restart complete!"

# Clean up everything (stop + remove volumes and test data)
clean: stop-all
    @echo "Cleaning up..."
    -docker rm syftbox-client-{{TEST_CLIENT1_NAME}}
    -docker rm syftbox-client-{{TEST_CLIENT2_NAME}}
    -docker rm syftbox-client-{{SYC_CLIENT_ALICE_NAME}}
    -docker rm syftbox-client-{{SYC_CLIENT_BOB_NAME}}
    -docker rm syftbox-client-{{SYC_CLIENT_CHARLIE_NAME}}
    -cd {{DOCKER_DIR}} && docker compose down -v
    -rm -rf {{TEST_CLIENTS_DIR}}
    @echo "Cleanup complete."

# Fix file permissions for client directories
fix-permissions:
    @echo "Fixing file permissions for client directories..."
    @if [ -d "{{TEST_CLIENTS_DIR}}" ]; then \
        sudo chown -R $(id -u):$(id -g) {{TEST_CLIENTS_DIR}} 2>/dev/null || true; \
        chmod -R 755 {{TEST_CLIENTS_DIR}} 2>/dev/null || true; \
        find {{TEST_CLIENTS_DIR}} -type f -exec chmod 644 {} \; 2>/dev/null || true; \
    fi

# Run the integration tests
test:
    @echo "Running integration tests..."
    @echo "Activating virtual environment and running core tests..."
    bash -c "uv run python -m pytest tests/ -m 'not syc' -v -s"
    @echo "Running Syft Crypto tests..."
    bash -c "uv run python -m pytest tests/ -m syc -v -s"

# Install test dependencies
install-deps:
    @echo "Installing test dependencies with uv..."
    uv venv --python 3.11
    uv pip install -r requirements-test.txt

# Run tests with setup and teardown
test-full: clean start-all
    @echo "Waiting for services to stabilize..."
    @sleep 10
    @echo "Running core integration tests..."
    -bash -c "uv run python -m pytest tests/ -m 'not syc' -v"
    @echo "Running Syft Crypto tests..."
    -bash -c "uv run python -m pytest tests/ -m syc -v"
    @just clean

test-syc flag='': clean start-syc
    @echo "Waiting for Syft Crypto services to stabilize..."
    @sleep 15
    @echo "Building syc CLI..."
    -rustup toolchain install 1.90.0 >/dev/null
    -rustup override set 1.90.0 >/dev/null
    -cargo build --manifest-path syft-crypto-core/cli/Cargo.toml --bin syc --locked
    @echo "Running Syft Crypto integration tests..."
    -bash -c "uv run python -m pytest tests/ -m syc -v -s"
    @if [ "{{flag}}" = "--inspect" ] || [ "{{flag}}" = "inspect" ]; then \
        echo "Inspect mode enabled: leaving containers and clients running. Run 'just clean' when finished."; \
    else \
        just clean; \
    fi

# Show logs for debugging
logs-server:
    docker logs syftbox-server -f

logs-client1:
    docker logs syftbox-client-{{TEST_CLIENT1_NAME}} -f

logs-client2:
    docker logs syftbox-client-{{TEST_CLIENT2_NAME}} -f

logs-alice:
    docker logs syftbox-client-{{SYC_CLIENT_ALICE_NAME}} -f

logs-bob:
    docker logs syftbox-client-{{SYC_CLIENT_BOB_NAME}} -f

logs-charlie:
    docker logs syftbox-client-{{SYC_CLIENT_CHARLIE_NAME}} -f

# Check service status
status:
    @echo "Service status:"
    @docker ps --filter "name=syftbox"
