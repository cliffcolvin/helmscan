package reports

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	helmscanTypes "github.com/cliffcolvin/helmscan/internal/helmScanTypes"
)

func CreateSafeFileName(input string) string {
	replacer := strings.NewReplacer(
		"/", "-",
		":", "-",
		".", "-",
		"@", "-",
		" ", "-",
		"_", "-",
	)
	return replacer.Replace(input)
}

func SaveToFile(report string, filename string) error {
	if err := os.MkdirAll("working-files/scans", 0755); err != nil {
		return fmt.Errorf("error creating working-files directory: %w", err)
	}

	baseDir := strings.TrimSuffix(filename, filepath.Ext(filename))
	scanDir := filepath.Join("working-files/scans", CreateSafeFileName(baseDir))
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		return fmt.Errorf("error creating scan directory: %w", err)
	}

	filepath := filepath.Join(scanDir, filename)
	err := os.WriteFile(filepath, []byte(report), 0644)
	if err != nil {
		return fmt.Errorf("error writing report to file: %w", err)
	}

	fmt.Printf("\nReport saved to: %s\n", filepath)
	return nil
}

func FormatMarkdownTable(headers []string, rows [][]string) string {
	var sb strings.Builder

	sb.WriteString("| " + strings.Join(headers, " | ") + " |\n")

	sb.WriteString("|" + strings.Repeat("---------|", len(headers)) + "\n")

	for _, row := range rows {
		sb.WriteString("| " + strings.Join(row, " | ") + " |\n")
	}

	return sb.String()
}

func SeverityValue(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func FormatSection(title string, content string) string {
	return fmt.Sprintf("### %s\n\n%s\n", title, content)
}

type SortableCVE struct {
	ID       string
	Severity string
	Images   []string
}

type SortableCVEList []SortableCVE

func (s SortableCVEList) Len() int      { return len(s) }
func (s SortableCVEList) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s SortableCVEList) Less(i, j int) bool {
	if SeverityValue(s[i].Severity) == SeverityValue(s[j].Severity) {
		return s[i].ID < s[j].ID
	}
	return SeverityValue(s[i].Severity) > SeverityValue(s[j].Severity)
}

func ConvertToJSONCVEs(cves map[string]map[string]helmscanTypes.Vulnerability) []CVE {
	var jsonCVEs []CVE
	var sortedCVEs SortableCVEList

	for cveID, imageVulns := range cves {
		var images []string
		var severity string
		for imageName, vuln := range imageVulns {
			images = append(images, imageName)
			severity = vuln.GetSeverity()
		}
		sortedCVEs = append(sortedCVEs, SortableCVE{
			ID:       cveID,
			Severity: severity,
			Images:   images,
		})
	}

	sort.Sort(sortedCVEs)

	for _, cve := range sortedCVEs {
		jsonCVEs = append(jsonCVEs, CVE{
			ID:             cve.ID,
			Severity:       cve.Severity,
			AffectedImages: cve.Images,
		})
	}

	return jsonCVEs
}

type SingleScanReport struct {
	ArtifactType string
	ArtifactRef  string
	Summary      SeveritySummary
	CVEs         []CVE
}

type SeveritySummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
}

func GenerateSingleScanReport(artifactType string, artifactRef string, vulns map[string]helmscanTypes.Vulnerability, generateJSON bool) string {
	report := SingleScanReport{
		ArtifactType: artifactType,
		ArtifactRef:  artifactRef,
		Summary:      countVulnerabilities(vulns),
		CVEs:         convertVulnerabilitiesToCVEs(vulns),
	}

	if generateJSON {
		return GenerateJSONSingleReport(report)
	}
	return GenerateMarkdownSingleReport(report)
}

func countVulnerabilities(vulns map[string]helmscanTypes.Vulnerability) SeveritySummary {
	summary := SeveritySummary{}
	for _, vuln := range vulns {
		switch strings.ToLower(vuln.GetSeverity()) {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		}
	}
	return summary
}

func convertVulnerabilitiesToCVEs(vulns map[string]helmscanTypes.Vulnerability) []CVE {
	var cves []CVE
	for id, vuln := range vulns {
		cves = append(cves, CVE{
			ID:       id,
			Severity: vuln.GetSeverity(),
		})
	}

	sort.Slice(cves, func(i, j int) bool {
		if SeverityValue(cves[i].Severity) == SeverityValue(cves[j].Severity) {
			return cves[i].ID < cves[j].ID
		}
		return SeverityValue(cves[i].Severity) > SeverityValue(cves[j].Severity)
	})

	return cves
}

func GenerateJSONSingleReport(report SingleScanReport) string {
	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error generating JSON report: %v", err)
	}
	return string(jsonBytes)
}

func GenerateMarkdownSingleReport(report SingleScanReport) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# %s Scan Report\n", strings.Title(report.ArtifactType)))
	sb.WriteString(fmt.Sprintf("## Artifact: %s\n\n", report.ArtifactRef))

	sb.WriteString("### Vulnerability Summary\n\n")
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Critical | %d |\n", report.Summary.Critical))
	sb.WriteString(fmt.Sprintf("| High | %d |\n", report.Summary.High))
	sb.WriteString(fmt.Sprintf("| Medium | %d |\n", report.Summary.Medium))
	sb.WriteString(fmt.Sprintf("| Low | %d |\n\n", report.Summary.Low))

	sb.WriteString("### Vulnerabilities\n\n")
	currentSeverity := ""
	for _, cve := range report.CVEs {
		if cve.Severity != currentSeverity {
			if currentSeverity != "" {
				sb.WriteString("\n")
			}
			sb.WriteString(fmt.Sprintf("#### %s\n", strings.Title(cve.Severity)))
			sb.WriteString("| CVE ID | Severity |\n")
			sb.WriteString("|---------|----------|\n")
			currentSeverity = cve.Severity
		}
		sb.WriteString(fmt.Sprintf("| %s | %s |\n", cve.ID, cve.Severity))
	}

	return sb.String()
}

func GenerateMarkdownReport(comparison helmscanTypes.HelmComparison) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("## Helm Chart Comparison Report %s/%s@%s to %s/%s@%s\n\n",
		comparison.Before.HelmRepo, comparison.Before.Name, comparison.Before.Version,
		comparison.After.HelmRepo, comparison.After.Name, comparison.After.Version))

	sb.WriteString("### CVE by Severity\n\n")
	sb.WriteString("| Severity | Count | Prev Count | Difference |\n")
	sb.WriteString("|----------|-------|------------|------------|\n")

	severities := []string{"critical", "high", "medium", "low"}
	prevCounts := make(map[string]int)
	currentCounts := make(map[string]int)

	for _, img := range comparison.Before.ContainsImages {
		for _, vuln := range img.Vulnerabilities {
			prevCounts[vuln.Severity]++
		}
	}
	for _, img := range comparison.After.ContainsImages {
		for _, vuln := range img.Vulnerabilities {
			currentCounts[vuln.Severity]++
		}
	}

	for _, severity := range severities {
		count := currentCounts[severity]
		prevCount := prevCounts[severity]
		difference := count - prevCount
		differenceStr := fmt.Sprintf("%+d", difference)

		sb.WriteString(fmt.Sprintf("| %s | %d | %d | %s |\n", severity, count, prevCount, differenceStr))
	}
	sb.WriteString("\n\n")

	sb.WriteString("### Images\n\n")
	sb.WriteString("| Image Name | Status | Before Repo | After Repo | Before Tag | After Tag |\n")
	sb.WriteString("|------------|--------|-------------|------------|------------|-----------|\n")

	var imageRows []string

	for name, images := range comparison.AddedImages {
		imageRows = append(imageRows, fmt.Sprintf("| %s | Added | - | %s | - | %s |",
			name, images[0].Repository, images[0].Tag))
	}

	for name, images := range comparison.RemovedImages {
		imageRows = append(imageRows, fmt.Sprintf("| %s | Removed | %s | - | %s | - |",
			name, images[0].Repository, images[0].Tag))
	}

	for name, images := range comparison.ChangedImages {
		imageRows = append(imageRows, fmt.Sprintf("| %s | Changed | %s | %s | %s | %s |",
			name, images[0].Repository, images[1].Repository, images[0].Tag, images[1].Tag))
	}

	for name, images := range comparison.UnChangedImages {
		imageRows = append(imageRows, fmt.Sprintf("| %s | Unchanged | %s | %s | %s | %s |",
			name, images[0].Repository, images[1].Repository, images[0].Tag, images[1].Tag))
	}

	sb.WriteString(strings.Join(imageRows, "\n"))
	sb.WriteString("\n\n")

	sb.WriteString("### Unchanged CVEs\n\n")
	sb.WriteString(sortAndFormatCVEs(comparison.UnchangedCVEs))
	sb.WriteString("\n\n")

	sb.WriteString("### Added CVEs\n\n")
	sb.WriteString(sortAndFormatCVEs(comparison.AddedCVEs))
	sb.WriteString("\n\n")

	sb.WriteString("### Removed CVEs\n\n")
	sb.WriteString(sortAndFormatCVEs(comparison.RemovedCVEs))
	sb.WriteString("\n")

	return sb.String()
}

func GenerateJSONReport(comparison helmscanTypes.HelmComparison) string {
	report := JSONReport{
		ReportType: "helm_comparison",
		Comparison: map[string]string{
			"before_chart": fmt.Sprintf("%s/%s@%s", comparison.Before.HelmRepo, comparison.Before.Name, comparison.Before.Version),
			"after_chart":  fmt.Sprintf("%s/%s@%s", comparison.After.HelmRepo, comparison.After.Name, comparison.After.Version),
		},
		Summary: Summary{
			SeverityCounts: GenerateJSONSeverityCounts(comparison),
			ImageChanges:   GenerateJSONImageChanges(comparison),
		},
		AddedCVEs:     ConvertToJSONCVEs(comparison.AddedCVEs),
		RemovedCVEs:   ConvertToJSONCVEs(comparison.RemovedCVEs),
		UnchangedCVEs: ConvertToJSONCVEs(comparison.UnchangedCVEs),
	}

	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error generating JSON report: %v", err)
	}
	return string(jsonBytes)
}

func sortAndFormatCVEs(cves map[string]map[string]helmscanTypes.Vulnerability) string {
	if len(cves) == 0 {
		return "No CVEs found.\n\n"
	}

	var sortedCVEs SortableCVEList
	for cveID, imageVulns := range cves {
		var images []string
		var severity string
		for imageName, vuln := range imageVulns {
			images = append(images, imageName)
			severity = vuln.GetSeverity()
		}
		sortedCVEs = append(sortedCVEs, SortableCVE{
			ID:       cveID,
			Severity: severity,
			Images:   images,
		})
	}

	sort.Sort(sortedCVEs)

	var sb strings.Builder
	sb.WriteString("| CVE ID | Severity | Affected Images |\n")
	sb.WriteString("|--------|----------|------------------|\n")

	currentSeverity := ""
	for _, cve := range sortedCVEs {
		if cve.Severity != currentSeverity {
			if currentSeverity != "" {
				sb.WriteString("\n")
			}
			sb.WriteString(fmt.Sprintf("#### %s\n", strings.Title(cve.Severity)))
			sb.WriteString("| CVE ID | Severity | Affected Images |\n")
			sb.WriteString("|--------|----------|------------------|\n")
			currentSeverity = cve.Severity
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", cve.ID, cve.Severity, strings.Join(cve.Images, ", ")))
	}
	return sb.String()
}

func GenerateJSONSeverityCounts(comparison helmscanTypes.HelmComparison) []SeverityCount {
	severities := []string{"critical", "high", "medium", "low"}
	counts := make([]SeverityCount, 0, len(severities))

	// Ensure each CVE is counted only once per image, as duplicate images may exist in the helm chart comparison
	beforeImages := make(map[string]*helmscanTypes.ContainerImage)
	afterImages := make(map[string]*helmscanTypes.ContainerImage)

	for _, img := range comparison.Before.ContainsImages {
		beforeImages[img.ImageName] = img
	}
	for _, img := range comparison.After.ContainsImages {
		afterImages[img.ImageName] = img
	}

	prevCounts := make(map[string]int)
	currentCounts := make(map[string]int)
	for _, img := range beforeImages {
		for _, vuln := range img.Vulnerabilities {
			prevCounts[vuln.Severity]++
		}
	}
	for _, img := range afterImages {
		for _, vuln := range img.Vulnerabilities {
			currentCounts[vuln.Severity]++
		}
	}

	for _, severity := range severities {
		current := currentCounts[severity]
		previous := prevCounts[severity]
		counts = append(counts, SeverityCount{
			Severity:   severity,
			Current:    current,
			Previous:   previous,
			Difference: current - previous,
		})
	}

	return counts
}

func GenerateJSONImageChanges(comparison helmscanTypes.HelmComparison) []ImageChange {
	var changes []ImageChange

	for name, images := range comparison.AddedImages {
		changes = append(changes, ImageChange{
			Name:      name,
			Status:    "Added",
			AfterRepo: images[0].Repository,
			AfterTag:  images[0].Tag,
		})
	}

	for name, images := range comparison.RemovedImages {
		changes = append(changes, ImageChange{
			Name:       name,
			Status:     "Removed",
			BeforeRepo: images[0].Repository,
			BeforeTag:  images[0].Tag,
		})
	}

	for name, images := range comparison.ChangedImages {
		changes = append(changes, ImageChange{
			Name:       name,
			Status:     "Changed",
			BeforeRepo: images[0].Repository,
			AfterRepo:  images[1].Repository,
			BeforeTag:  images[0].Tag,
			AfterTag:   images[1].Tag,
		})
	}

	for name, images := range comparison.UnChangedImages {
		changes = append(changes, ImageChange{
			Name:       name,
			Status:     "Unchanged",
			BeforeRepo: images[0].Repository,
			AfterRepo:  images[0].Repository,
			BeforeTag:  images[0].Tag,
			AfterTag:   images[0].Tag,
		})
	}

	return changes
}
