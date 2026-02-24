# SCARABEO Release Guide

## Release Process

### Pre-Release Checklist

1. **Version Update**
   ```bash
   # Update VERSION file
   echo "1.0.0" > VERSION
   
   # Update scarabeo/version.py
   # Update CHANGELOG.md with release notes
   ```

2. **Run Release Checks**
   ```bash
   make release-check
   ```

3. **Build All Images**
   ```bash
   make build-all-images
   ```

4. **Test Deployment**
   ```bash
   # Local testing
   make up-all
   
   # Verify all services healthy
   curl http://localhost:8000/healthz
   curl http://localhost:8001/healthz
   ```

### Creating a Release

1. **Create Release Tag**
   ```bash
   make release-tag VERSION=1.0.0
   ```

2. **Push Release**
   ```bash
   git push origin --tags
   ```

3. **Create GitHub Release**
   - Go to GitHub Releases
   - Create new release from tag
   - Copy CHANGELOG.md entries
   - Attach built images or provide pull commands

### Post-Release

1. **Update Documentation**
   - Update README.md with new version
   - Update deployment guides

2. **Notify Stakeholders**
   - Send release announcement
   - Update internal documentation

## Versioning Policy

SCARABEO follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Version Format

```
MAJOR.MINOR.PATCH
```

Examples:
- `1.0.0` - Initial release
- `1.1.0` - New analyzer added
- `1.1.1` - Bug fix in existing analyzer
- `2.0.0` - Breaking API change

## Release Artifacts

### Docker Images

| Image | Description |
|-------|-------------|
| `scarabeo/ingest:TAG` | Ingest service |
| `scarabeo/orchestrator:TAG` | Orchestrator service |
| `scarabeo/worker:TAG` | Worker service |
| `scarabeo/cli:TAG` | CLI console |
| `scarabeo/triage-universal:TAG` | Triage analyzer |
| `scarabeo/pe-analyzer:TAG` | PE analyzer |
| `scarabeo/elf-analyzer:TAG` | ELF analyzer |
| `scarabeo/script-analyzer:TAG` | Script analyzer |
| `scarabeo/doc-analyzer:TAG` | Document analyzer |
| `scarabeo/archive-analyzer:TAG` | Archive analyzer |
| `scarabeo/similarity-analyzer:TAG` | Similarity analyzer |
| `scarabeo/yara-analyzer:TAG` | YARA analyzer |
| `scarabeo/capa-analyzer:TAG` | CAPA analyzer |

### Kubernetes Manifests

Located in `infra/k8s/`:
- `namespace.yaml`
- `postgres.yaml`
- `redis.yaml`
- `minio.yaml`
- `ingest.yaml`
- `orchestrator.yaml`
- `worker.yaml`
- `cli.yaml`

## Rollback Procedure

If a release has issues:

1. **Stop New Deployments**
   ```bash
   kubectl rollout pause deployment/scarabeo-ingest -n scarabeo
   ```

2. **Rollback to Previous Version**
   ```bash
   kubectl rollout undo deployment/scarabeo-ingest -n scarabeo
   ```

3. **Verify Rollback**
   ```bash
   kubectl rollout status deployment/scarabeo-ingest -n scarabeo
   ```

## Hotfix Process

For critical bugs:

1. Create hotfix branch from release tag
2. Fix and test
3. Create patch release (increment PATCH version)
4. Follow release process
