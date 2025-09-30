package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	helmscanTypes "github.com/cliffcolvin/helmscan/internal/helmScanTypes"
	"github.com/cliffcolvin/helmscan/internal/helmscan"
	"github.com/cliffcolvin/helmscan/internal/imageScan"
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

	if err := imageScan.CheckTrivyInstallation(); err != nil {
		logger.Fatalf("Trivy installation check failed: %v", err)
	}
}

func main() {
	if err := os.MkdirAll("working-files", os.ModePerm); err != nil {
		logger.Fatalf("Failed to create working-files directory: %v", err)
	}

	compare := flag.Bool("compare", false, "Enable comparison mode")
	jsonOutput := flag.Bool("json", false, "Output in JSON format")
	report := flag.Bool("report", false, "Generate a report file")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		logger.Fatal("At least one artifact reference is required")
	}

	if *compare {
		if len(args) != 2 {
			logger.Fatal("Comparison mode requires exactly two artifacts")
		}
		compareArtifacts(args[0], args[1], *jsonOutput, *report)
	} else {
		if len(args) > 1 {
			logger.Fatal("Too many arguments for single artifact scan")
		}
		scanSingleArtifact(args[0], *jsonOutput, *report)
	}
}

func scanSingleArtifact(artifactRef string, jsonOutput bool, report bool) {
	if isHelmChart(artifactRef) {
		scanSingleHelmChart(artifactRef, jsonOutput, report)
	} else {
		scanSingleImage(artifactRef, jsonOutput, report)
	}
}

func compareArtifacts(ref1, ref2 string, jsonOutput bool, report bool) {
	if isHelmChart(ref1) != isHelmChart(ref2) {
		logger.Fatal("Cannot compare a Helm chart with a Docker image")
	}

	if isHelmChart(ref1) {
		compareHelmCharts(ref1, ref2, jsonOutput, report)
	} else {
		compareImages(ref1, ref2, jsonOutput, report)
	}
}

func isHelmChart(ref string) bool {
	return strings.Contains(ref, "/") && strings.Contains(ref, "@")
}

func scanSingleImage(imageURL string, jsonOutput bool, report bool) {
	logger.Infof("Scanning image: %s", imageURL)
	result, err := imageScan.ScanImage(imageURL)
	if err != nil {
		logger.Errorf("Error scanning image: %v", err)
		return
	}

	reportOutput := imageScan.GenerateReport(&helmscanTypes.ImageComparisonReport{
		Image2: result,
	}, jsonOutput, report)

	fmt.Println(reportOutput)
}

func scanSingleHelmChart(chartRef string, jsonOutput bool, report bool) {
	logger.Infof("Scanning Helm chart: %s", chartRef)
	parts := strings.Split(chartRef, "@")
	if len(parts) != 2 {
		logger.Fatalf("Invalid Helm chart reference. Expected format: repo/chart@version")
	}
	result, err := helmscan.Scan(chartRef)
	if err != nil {
		logger.Errorf("Error scanning Helm chart: %v", err)
		return
	}

	comparison := helmscan.CompareHelmCharts(helmscanTypes.HelmChart{}, result)
	helmscan.GenerateReport(comparison, jsonOutput, report)
}

func compareHelmCharts(chartRef1, chartRef2 string, jsonOutput bool, report bool) {
	parts1 := strings.Split(chartRef1, "@")
	parts2 := strings.Split(chartRef2, "@")
	if len(parts1) != 2 || len(parts2) != 2 {
		logger.Fatalf("Invalid Helm chart reference(s). Expected format: repo/chart@version")
	}

	logger.Infof("Comparing Helm charts: %s and %s", chartRef1, chartRef2)

	scannedChart1, err := helmscan.Scan(chartRef1)
	if err != nil {
		logger.Errorf("Error scanning first Helm chart: %v", err)
		return
	}

	scannedChart2, err := helmscan.Scan(chartRef2)
	if err != nil {
		logger.Errorf("Error scanning second Helm chart: %v", err)
		return
	}

	comparison := helmscan.CompareHelmCharts(scannedChart1, scannedChart2)
	helmscan.GenerateReport(comparison, jsonOutput, report)

}

func compareImages(imageURL1, imageURL2 string, jsonOutput bool, report bool) {
	if imageURL1 == "" || imageURL2 == "" {
		fmt.Print("Enter the first image URL: ")
		imageURL1 = getUserInput()
		fmt.Print("Enter the second image URL: ")
		imageURL2 = getUserInput()
	}

	scan1, err := imageScan.ScanImage(imageURL1)
	if err != nil {
		logger.Errorf("Error scanning first image: %v", err)
		return
	}

	scan2, err := imageScan.ScanImage(imageURL2)
	if err != nil {
		logger.Errorf("Error scanning second image: %v", err)
		return
	}

	comparison := imageScan.CompareScans(scan1, scan2)
	reportOutput := imageScan.GenerateReport(comparison, jsonOutput, report)

	fmt.Println(reportOutput)
}

func getUserInput() string {
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}
