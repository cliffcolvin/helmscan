# helmscan
Container Image and Helm Chart CVE comparison tool

This tool allows you to scan and compare Container images or Helm charts and analyze their CVE (Common Vulnerabilities and Exposures) reports.
When comparing Helm charts, the tool will download the charts and scan every container image in the chart.

## Installation

### Using Homebrew
```bash
brew tap cliffcolvin/tap
brew install helmscan
```

This will automatically install all required dependencies.

## Prerequisites
The following tools are required and will be automatically installed via Homebrew:
- [Trivy](https://github.com/aquasecurity/trivy) - for vulnerability scanning
- [Helm](https://helm.sh) - for chart operations
- [yq](https://github.com/mikefarah/yq) - for YAML processing
- [jq](https://stedolan.github.io/jq/) - for JSON processing

## Usage

The tool supports two main operations:
1. Single artifact scanning
2. Artifact comparison

### Single Artifact Scanning

```bash
helmscan [--json] [--report] [--ignore-unfixed] <artifact>
```

Examples:
```bash
# Scan a Docker image
helmscan --json --report docker.io/library/ubuntu:22.04

# Scan a Helm chart
helmscan --report myrepo/mychart@1.0.0

# Scan showing only fixable vulnerabilities
helmscan --report --ignore-unfixed myrepo/mychart@1.0.0
```

### Artifact Comparison

```bash
helmscan --compare [--json] [--report] [--ignore-unfixed] <artifact1> <artifact2>
```

Examples:
```bash
# Compare Docker images
helmscan --compare --json --report docker.io/library/ubuntu:20.04 docker.io/library/ubuntu:22.04

# Compare Helm charts
helmscan --compare --report myrepo/mychart@1.0.0 myrepo/mychart@2.0.0

# Compare showing only fixable vulnerabilities
helmscan --compare --report --ignore-unfixed myrepo/mychart@1.0.0 myrepo/mychart@2.0.0
```

### Flags
- `--compare`: Enable comparison mode (requires exactly 2 artifacts)
- `--report`: Generate a report file (optional, saves to `working-files/scans/`)
- `--json`: Output in JSON format (optional, defaults to markdown)
- `--ignore-unfixed`: Ignore unfixed vulnerabilities in Trivy scans (optional, shows only CVEs with available fixes)

### Output

Reports are automatically saved in the `working-files` directory when using `--report`:
```
working-files/
  scans/
    {scan-name}/
      scan_report.{md,json}
  tmp/
    trivy_output/
      {image}_trivy_output.json
```


## Contributing

### Building
```bash
go build -o helmscan cmd/app/main.go
```
This will build the binary for the current platform.

Installing Trivy:
```bash
brew install aquasecurity/trivy/trivy
```