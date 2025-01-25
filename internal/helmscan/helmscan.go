package helmscan

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	helmscanTypes "github.com/cliffcolvin/helmscan/internal/helmScanTypes"
	"github.com/cliffcolvin/helmscan/internal/imageScan"
	"github.com/cliffcolvin/helmscan/internal/reports"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli"
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

	logger.Info("Application started")

	if err := imageScan.CheckTrivyInstallation(); err != nil {
		logger.Fatalf("Trivy installation check failed: %v", err)
	}
}

func Scan(chartRef string) (helmscanTypes.HelmChart, error) {
	if err := os.MkdirAll("working-files/tmp/helm_output", 0755); err != nil {
		return helmscanTypes.HelmChart{}, fmt.Errorf("error creating working-files/tmp/helm_output directory: %w", err)
	}

	repoName, chartName, version, err := parseChartReference(chartRef)
	if err != nil {
		return helmscanTypes.HelmChart{}, err
	}

	helm_repo_update_cmd := exec.Command("helm", "repo", "update")
	output, err := helm_repo_update_cmd.CombinedOutput()
	if err != nil {
		logger.Errorf("Error updating Helm repo: %v\nOutput: %s", err, string(output))
		return helmscanTypes.HelmChart{}, fmt.Errorf("error updating Helm repo: %v\nOutput: %s", err, string(output))
	}
	logger.Infof("Helm repo update output: %s", string(output))

	cmd := exec.Command("helm", "template", fmt.Sprintf("%s/%s", repoName, chartName), "--version", version)
	output, err = cmd.CombinedOutput()
	if err != nil {
		logger.Errorf("Error templating chart: %v\nOutput: %s", err, string(output))
		return helmscanTypes.HelmChart{}, fmt.Errorf("error templating chart: %v\nOutput: %s", err, string(output))
	}

	outputFileName := fmt.Sprintf("working-files/tmp/helm_output/%s_%s_%s_helm_output.yaml", repoName, chartName, version)
	err = os.WriteFile(outputFileName, output, 0644)
	if err != nil {
		return helmscanTypes.HelmChart{}, fmt.Errorf("error saving helm output to file: %w", err)
	}

	images, err := extractImagesFromYAML(output)
	if err != nil {
		return helmscanTypes.HelmChart{}, fmt.Errorf("error extracting images: %w", err)
	}

	helmChart := helmscanTypes.HelmChart{
		Name:           chartName,
		Version:        version,
		HelmRepo:       repoName,
		ContainsImages: make([]*helmscanTypes.ContainerImage, len(images)),
	}

	var scanErrors []string
	for id, img := range images {
		imageName := fmt.Sprintf("%s/%s:%s", img.Repository, img.ImageName, img.Tag)
		scanResult, err := imageScan.ScanImage(imageName)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("error scanning image %s: %v", img.ImageName, err))
		} else {
			tmpVulns := make(map[string]helmscanTypes.Vulnerability)
			for i := range scanResult.VulnList {
				if _, exists := tmpVulns[scanResult.VulnList[i].ID]; !exists {
					tmpVulns[scanResult.VulnList[i].ID] = scanResult.VulnList[i]
				}
			}
			helmChart.ContainsImages[id] = &helmscanTypes.ContainerImage{
				Repository:      img.Repository,
				ImageName:       img.ImageName,
				Tag:             img.Tag,
				ScanResult:      scanResult,
				Vulnerabilities: tmpVulns,
			}
		}
	}

	if len(scanErrors) > 0 {
		return helmChart, fmt.Errorf("errors occurred during image scanning:\n%s", strings.Join(scanErrors, "\n"))
	}

	return helmChart, nil
}

func CompareHelmCharts(before, after helmscanTypes.HelmChart) helmscanTypes.HelmComparison {
	comparison := helmscanTypes.HelmComparison{
		Before:          before,
		After:           after,
		AddedImages:     make(map[string][]*helmscanTypes.ContainerImage),
		RemovedImages:   make(map[string][]*helmscanTypes.ContainerImage),
		ChangedImages:   make(map[string][]*helmscanTypes.ContainerImage),
		UnChangedImages: make(map[string][]*helmscanTypes.ContainerImage),
		RemovedCVEs:     make(map[string]map[string]helmscanTypes.Vulnerability),
		AddedCVEs:       make(map[string]map[string]helmscanTypes.Vulnerability),
		UnchangedCVEs:   make(map[string]map[string]helmscanTypes.Vulnerability),
	}

	beforeImages := make(map[string]*helmscanTypes.ContainerImage)
	afterImages := make(map[string]*helmscanTypes.ContainerImage)

	for _, img := range before.ContainsImages {
		beforeImages[img.ImageName] = img
	}

	for _, img := range after.ContainsImages {
		afterImages[img.ImageName] = img
	}

	for name, beforeImg := range beforeImages {
		if afterImg, exists := afterImages[name]; exists {
			if beforeImg.Tag != afterImg.Tag {
				comparison.ChangedImages[name] = []*helmscanTypes.ContainerImage{beforeImg, afterImg}
				compareImageVulnerabilities(beforeImg, afterImg, &comparison)
			} else {
				comparison.UnChangedImages[name] = []*helmscanTypes.ContainerImage{beforeImg, afterImg}
				for ID, vuln := range beforeImg.Vulnerabilities {
					if _, exists := comparison.UnchangedCVEs[ID]; !exists {
						comparison.UnchangedCVEs[ID] = make(map[string]helmscanTypes.Vulnerability)
					}
					comparison.UnchangedCVEs[ID][name] = vuln
				}
			}
		} else {
			comparison.RemovedImages[name] = []*helmscanTypes.ContainerImage{beforeImg}
			for ID, vuln := range beforeImg.Vulnerabilities {
				if _, exists := comparison.RemovedCVEs[ID]; !exists {
					comparison.RemovedCVEs[ID] = make(map[string]helmscanTypes.Vulnerability)
					comparison.RemovedCVEs[ID][name] = vuln
				} else {
					comparison.RemovedCVEs[ID][name] = vuln
				}
			}
		}
	}

	for name, afterImg := range afterImages {
		if _, exists := beforeImages[name]; !exists {
			comparison.AddedImages[name] = []*helmscanTypes.ContainerImage{afterImg}
			for ID, vuln := range afterImg.Vulnerabilities {
				if _, exists := comparison.AddedCVEs[ID]; !exists {
					comparison.AddedCVEs[ID] = make(map[string]helmscanTypes.Vulnerability)
					comparison.AddedCVEs[ID][name] = vuln
				} else {
					comparison.AddedCVEs[ID][name] = vuln
				}
			}
		}
	}

	return comparison
}

func compareImageVulnerabilities(before, after *helmscanTypes.ContainerImage, comparison *helmscanTypes.HelmComparison) {
	for id, vuln := range before.Vulnerabilities {
		if _, exists := after.Vulnerabilities[id]; !exists {
			if _, exists := comparison.RemovedCVEs[id]; !exists {
				comparison.RemovedCVEs[id] = make(map[string]helmscanTypes.Vulnerability)
			}
			comparison.RemovedCVEs[id][before.ImageName] = vuln
		} else {
			if _, exists := comparison.UnchangedCVEs[id]; !exists {
				comparison.UnchangedCVEs[id] = make(map[string]helmscanTypes.Vulnerability)
			}
			comparison.UnchangedCVEs[id][before.ImageName] = vuln
		}
	}

	for id, vuln := range after.Vulnerabilities {
		if _, exists := before.Vulnerabilities[id]; !exists {
			if _, exists := comparison.AddedCVEs[id]; !exists {
				comparison.AddedCVEs[id] = make(map[string]helmscanTypes.Vulnerability)
			}
			comparison.AddedCVEs[id][after.ImageName] = vuln
		}
	}
}

func extractImagesFromYAML(yamlData []byte) ([]*helmscanTypes.ContainerImage, error) {
	cmd := exec.Command("bash", "-c", `yq '.. | .image? | select(.)'`)
	cmd.Stdin = bytes.NewReader(yamlData)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error extracting images: %w", err)
	}

	imageStrings := strings.Split(strings.TrimSpace(string(output)), "\n")

	var images []*helmscanTypes.ContainerImage
	for _, imageString := range imageStrings {
		imageString = strings.Trim(imageString, "\"")
		image := parseImageString(imageString)
		images = append(images, image)
	}

	return images, nil
}

func parseImageString(imageString string) *helmscanTypes.ContainerImage {
	parts := strings.Split(imageString, ":")
	var repository, imageName, tag string

	if len(parts) > 1 {
		tag = parts[len(parts)-1]
		repoAndImage := strings.Join(parts[:len(parts)-1], ":")
		repoParts := strings.Split(repoAndImage, "/")
		if len(repoParts) > 1 {
			imageName = repoParts[len(repoParts)-1]
			repository = strings.Join(repoParts[:len(repoParts)-1], "/")
		} else {
			imageName = repoAndImage
		}
	} else {
		repoParts := strings.Split(imageString, "/")
		if len(repoParts) > 1 {
			imageName = repoParts[len(repoParts)-1]
			repository = strings.Join(repoParts[:len(repoParts)-1], "/")
		} else {
			imageName = imageString
		}
		tag = "latest"
	}

	return &helmscanTypes.ContainerImage{
		Repository: repository,
		ImageName:  imageName,
		Tag:        tag,
	}
}

func parseChartReference(chartRef string) (string, string, string, error) {
	parts := strings.Split(chartRef, "/")
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("invalid chart reference: %s", chartRef)
	}
	repoAndChart := parts[1]
	repoParts := strings.Split(repoAndChart, "@")
	if len(repoParts) != 2 {
		return "", "", "", fmt.Errorf("invalid chart reference: %s", chartRef)
	}
	return parts[0], repoParts[0], repoParts[1], nil
}

func downloadChart(repoName, chartName, version, destDir string) (string, error) {
	settings := cli.New()
	actionConfig := new(action.Configuration)
	client := action.NewInstall(actionConfig)
	client.DryRun = true
	client.ReleaseName = "test"
	client.Replace = true
	client.ClientOnly = true
	client.IncludeCRDs = false

	cp, err := client.ChartPathOptions.LocateChart(fmt.Sprintf("%s/%s", repoName, chartName), settings)
	if err != nil {
		return "", fmt.Errorf("error locating chart: %w", err)
	}

	chartPath := filepath.Join(destDir, filepath.Base(cp))
	err = os.Rename(cp, chartPath)
	if err != nil {
		return "", fmt.Errorf("error moving chart: %w", err)
	}

	return chartPath, nil
}

func GenerateReport(comparison helmscanTypes.HelmComparison, generateJSON bool, generateMD bool) string {
	generator := NewHelmReportGenerator(comparison)
	return reports.GenerateReport(generator, generateJSON, generateMD)
}

func GenerateSingleScanReport(chart helmscanTypes.HelmChart, jsonOutput bool) string {
	vulns := make(map[string]helmscanTypes.Vulnerability)
	for _, img := range chart.ContainsImages {
		for id, v := range img.Vulnerabilities {
			vulns[fmt.Sprintf("%s:%s", img.ImageName, id)] = v
		}
	}

	chartRef := fmt.Sprintf("%s/%s@%s", chart.HelmRepo, chart.Name, chart.Version)
	return reports.GenerateSingleScanReport("helm", chartRef, vulns, jsonOutput)
}

func scanSingleHelmChart(chartRef string, saveReport bool, jsonOutput bool) {
	logger.Infof("Scanning Helm chart: %s", chartRef)
	result, err := Scan(chartRef)
	if err != nil {
		logger.Errorf("Error scanning Helm chart: %v", err)
		return
	}

	report := GenerateSingleScanReport(result, jsonOutput)

	if saveReport {
		ext := ".md"
		if jsonOutput {
			ext = ".json"
		}
		filename := fmt.Sprintf("helm_scan_%s%s", reports.CreateSafeFileName(chartRef), ext)
		if err := reports.SaveToFile(report, filename); err != nil {
			logger.Errorf("Error saving report: %v", err)
		}
	}

	fmt.Println(report)
}
