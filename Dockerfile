# SCARABEO Root Dockerfile
# This is a meta-Dockerfile for building all SCARABEO images
# Use docker-compose or individual service Dockerfiles for actual builds

FROM scratch

LABEL description="SCARABEO Analysis Framework - Root Image"
LABEL version="1.0.0"

# This is a placeholder root Dockerfile
# Use the following commands to build all images:
#
#   make build-all-images
#
# Or build individual services:
#
#   docker build -t scarabeo/ingest:latest -f services/ingest/Dockerfile .
#   docker build -t scarabeo/orchestrator:latest -f services/orchestrator/Dockerfile .
#   docker build -t scarabeo/worker:latest -f services/worker/Dockerfile .
#   docker build -t scarabeo/cli:latest -f services/cli/Dockerfile .
#   docker build -t scarabeo/triage-universal:latest -f analyzers/triage-universal/Dockerfile .
#   docker build -t scarabeo/pe-analyzer:latest -f analyzers/pe-analyzer/Dockerfile .
#   docker build -t scarabeo/elf-analyzer:latest -f analyzers/elf-analyzer/Dockerfile .
#   docker build -t scarabeo/script-analyzer:latest -f analyzers/script-analyzer/Dockerfile .
#   docker build -t scarabeo/doc-analyzer:latest -f analyzers/doc-analyzer/Dockerfile .
#   docker build -t scarabeo/archive-analyzer:latest -f analyzers/archive-analyzer/Dockerfile .
#   docker build -t scarabeo/similarity-analyzer:latest -f analyzers/similarity-analyzer/Dockerfile .
#   docker build -t scarabeo/yara-analyzer:latest -f analyzers/yara-analyzer/Dockerfile .
#   docker build -t scarabeo/capa-analyzer:latest -f analyzers/capa-analyzer/Dockerfile .

CMD ["/bin/sh", "-c", "echo 'Use docker-compose or individual service Dockerfiles'"]
