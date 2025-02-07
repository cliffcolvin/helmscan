package imageScan

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	helmscanTypes "github.com/cliffcolvin/helmscan/internal/helmScanTypes"
	"github.com/cliffcolvin/helmscan/internal/reports"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.SugaredLogger

func init() {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.AddSync(os.Stdout),
		zap.InfoLevel,
	)

	zapLogger := zap.New(core)
	defer zapLogger.Sync()

	logger = zapLogger.Sugar()
}

func ScanImage(imageName string) (helmscanTypes.ScanResult, error) {
	if strings.Contains(imageName, "alpine") {
		return helmscanTypes.ScanResult{}, nil
	}

	if err := os.MkdirAll("working-files/tmp/trivy_output", 0755); err != nil {
		return helmscanTypes.ScanResult{}, fmt.Errorf("failed to create working directory: %w", err)
	}

	safeFileName := reports.CreateSafeFileName(imageName)
	outputFile := fmt.Sprintf("working-files/tmp/trivy_output/%s_trivy_output.json", safeFileName)

	cmd := exec.Command("trivy", "image",
		"-f", "json",
		"-o", outputFile,
		"--severity", "HIGH,MEDIUM,LOW,CRITICAL",
		"--pkg-types", "os,library",
		"--scanners", "vuln,secret,misconfig",
		imageName)

	combinedOutput, err := cmd.CombinedOutput()
	if err != nil {
		return helmscanTypes.ScanResult{}, fmt.Errorf("error running command: %w\nOutput: %s", err, string(combinedOutput))
	}

	jsonData, err := os.ReadFile(outputFile)
	if err != nil {
		return helmscanTypes.ScanResult{}, fmt.Errorf("error reading %s: %w", outputFile, err)
	}

	vulns := extractVulnerabilities(string(jsonData))

	result := helmscanTypes.ScanResult{
		Image:           imageName,
		Vulnerabilities: countVulnerabilities(vulns),
		VulnsByLevel:    groupVulnerabilitiesByLevel(vulns),
		VulnList:        vulns,
	}

	return result, nil
}

func countVulnerabilities(vulns []helmscanTypes.Vulnerability) helmscanTypes.SeverityCounts {
	counts := helmscanTypes.SeverityCounts{}
	for _, vuln := range vulns {
		incrementSeverityCount(&counts, vuln.Severity)
	}
	return counts
}

func groupVulnerabilitiesByLevel(vulns []helmscanTypes.Vulnerability) map[string][]string {
	grouped := make(map[string][]string)
	for _, vuln := range vulns {
		grouped[vuln.Severity] = append(grouped[vuln.Severity], vuln.ID)
	}
	return grouped
}

func CompareScans(firstScan, secondScan helmscanTypes.ScanResult) *helmscanTypes.ImageComparisonReport {
	comparison := &helmscanTypes.ImageComparisonReport{
		Image1:        firstScan,
		Image2:        secondScan,
		RemovedCVEs:   make(map[string][]helmscanTypes.Vulnerability),
		AddedCVEs:     make(map[string][]helmscanTypes.Vulnerability),
		UnchangedCVEs: make(map[string][]helmscanTypes.Vulnerability),
	}

	firstVulns := make(map[string]helmscanTypes.Vulnerability)
	for _, vuln := range firstScan.VulnList {
		firstVulns[vuln.ID] = vuln
	}

	secondVulns := make(map[string]helmscanTypes.Vulnerability)
	for _, vuln := range secondScan.VulnList {
		secondVulns[vuln.ID] = vuln
	}

	for ID, vuln := range firstVulns {
		if _, exists := secondVulns[ID]; exists {
			comparison.UnchangedCVEs[vuln.Severity] = append(comparison.UnchangedCVEs[vuln.Severity], vuln)
		} else {
			comparison.RemovedCVEs[vuln.Severity] = append(comparison.RemovedCVEs[vuln.Severity], vuln)
		}
	}

	for ID, vuln := range secondVulns {
		if _, exists := firstVulns[ID]; !exists {
			comparison.AddedCVEs[vuln.Severity] = append(comparison.AddedCVEs[vuln.Severity], vuln)
		}
	}

	return comparison
}

func extractVulnerabilities(scan string) []helmscanTypes.Vulnerability {
	var result struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
				Severity        string `json:"Severity"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	err := json.Unmarshal([]byte(scan), &result)
	if err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		return nil
	}

	var vulns []helmscanTypes.Vulnerability
	for _, res := range result.Results {
		for _, vuln := range res.Vulnerabilities {
			vulns = append(vulns, helmscanTypes.Vulnerability{
				ID:       vuln.VulnerabilityID,
				Severity: strings.ToLower(vuln.Severity),
			})
		}
	}

	return vulns
}

func incrementSeverityCount(counts *helmscanTypes.SeverityCounts, severity string) {
	switch severity {
	case "low":
		counts.Low++
	case "medium":
		counts.Medium++
	case "high":
		counts.High++
	case "critical":
		counts.Critical++
	}
}

func difference(a, b []string) []string {
	bMap := make(map[string]bool)
	for _, v := range b {
		bMap[v] = true
	}

	var diff []string
	for _, v := range a {
		if !bMap[v] {
			diff = append(diff, v)
		}
	}
	return diff
}

func CheckTrivyInstallation() error {
	_, err := exec.LookPath("trivy")
	if err != nil {
		return fmt.Errorf("Trivy is not installed. Please install Trivy and ensure it's in your PATH")
	}

	cmd := exec.Command("trivy", "--version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("Failed to get Trivy version: %v", err)
	}

	version := strings.TrimSpace(strings.TrimPrefix(string(output), "Version: "))
	fmt.Printf("Trivy version %s is installed.\n", version)

	return nil
}

func calculateDifference(before, after map[string][]string) map[string][]helmscanTypes.Vulnerability {
	diff := make(map[string][]helmscanTypes.Vulnerability)

	for severity, vulns := range before {
		for _, vuln := range vulns {
			if !contains(after[severity], vuln) {
				diff[severity] = append(diff[severity], helmscanTypes.Vulnerability{
					ID:       vuln,
					Severity: severity,
				})
			}
		}
	}

	return diff
}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func GenerateReport(comparison *helmscanTypes.ImageComparisonReport, generateJSON bool, generateMD bool) string {
	generator := NewImageReportGenerator(comparison)
	return reports.GenerateReport(generator, generateJSON, generateMD)
}

func scanSingleImage(imageURL string, saveReport bool, jsonOutput bool) {
	logger.Infof("Scanning image: %s", imageURL)
	result, err := ScanImage(imageURL)
	if err != nil {
		logger.Errorf("Error scanning image: %v", err)
		return
	}

	vulns := make(map[string]helmscanTypes.Vulnerability)
	for _, v := range result.VulnList {
		vulns[v.ID] = v
	}

	report := reports.GenerateSingleScanReport("image", imageURL, vulns, jsonOutput)

	if saveReport {
		ext := ".md"
		if jsonOutput {
			ext = ".json"
		}
		filename := fmt.Sprintf("image_scan_%s%s", reports.CreateSafeFileName(imageURL), ext)
		if err := reports.SaveToFile(report, filename); err != nil {
			logger.Errorf("Error saving report: %v", err)
		}
	}

	fmt.Println(report)
}
