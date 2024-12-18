package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/cliffcolvin/helmscan/internal/helmscan"
	"github.com/cliffcolvin/helmscan/internal/imageScan"
	"github.com/cliffcolvin/helmscan/internal/reports"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.SugaredLogger

func init() {
	// Create a custom encoder config
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	// Create a custom core that writes to console
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.AddSync(os.Stdout),
		zap.InfoLevel,
	)

	// Create a logger with the custom core
	zapLogger := zap.New(core)
	defer zapLogger.Sync()

	// Create a sugared logger
	logger = zapLogger.Sugar()

	logger.Info("Application started")

	// Check Trivy installation
	if err := imageScan.CheckTrivyInstallation(); err != nil {
		logger.Fatalf("Trivy installation check failed: %v", err)
	}
}

func main() {
	// Ensure the working-files directory exists
	if err := ensureWorkingFilesDir(); err != nil {
		logger.Fatalf("Failed to create working-files directory: %v", err)
	}

	compareFlag := flag.Bool("compare", false, "Compare two images or Helm charts")
	reportFlag := flag.Bool("report", false, "Save the report to a file")
	jsonFlag := flag.Bool("json", false, "Output report in JSON format")
	flag.Parse()
	args := flag.Args()

	if *compareFlag {
		if len(args) != 2 {
			logger.Fatalf("For comparison, please provide exactly two image URLs or Helm chart references. Got: %v", args)
		}
		compareArtifacts(args[0], args[1], *reportFlag, *jsonFlag)
	} else if len(args) == 1 {
		scanSingleArtifact(args[0], *reportFlag, *jsonFlag)
	} else if len(args) == 0 {
		runInteractiveMenu()
	} else {
		logger.Fatal("Invalid number of arguments. Please provide one artifact reference for scanning or use --compare with two references")
	}
}

func runInteractiveMenu() {
	for {
		printMenu()
		choice := getUserInput()

		switch choice {
		case "1":
			scanArtifact()
		case "2":
			compareArtifacts("", "", true, false)
		case "3":
			logger.Info("Exiting the program. Goodbye!")
			return
		default:
			logger.Warn("Invalid option. Please try again.")
		}
	}
}

func printMenu() {
	fmt.Println("\n--- Artifact Security Scanner Menu ---")
	fmt.Println("1. Scan a single image or Helm chart")
	fmt.Println("2. Compare two images or Helm charts")
	fmt.Println("3. Exit")
	fmt.Print("Enter your choice (1-3): ")
}

func getUserInput() string {
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func scanSingleArtifact(artifactRef string, saveReport bool, jsonOutput bool) {
	if isHelmChart(artifactRef) {
		scanSingleHelmChart(artifactRef, saveReport, jsonOutput)
	} else {
		scanSingleImage(artifactRef, saveReport, jsonOutput)
	}
}

func scanArtifact() {
	fmt.Print("Enter the image URL or Helm chart reference to scan: ")
	artifactRef := getUserInput()
	scanSingleArtifact(artifactRef, true, false)
}

func compareArtifacts(ref1, ref2 string, saveReport bool, jsonOutput bool) {
	if ref1 == "" || ref2 == "" {
		fmt.Print("Enter the first image URL or Helm chart reference: ")
		ref1 = getUserInput()
		fmt.Print("Enter the second image URL or Helm chart reference: ")
		ref2 = getUserInput()
	}

	logger.Infof("Comparing artifacts: %s and %s", ref1, ref2)

	if isHelmChart(ref1) && isHelmChart(ref2) {
		compareHelmCharts(ref1, ref2, saveReport, jsonOutput)
	} else if !isHelmChart(ref1) && !isHelmChart(ref2) {
		compareImages(ref1, ref2, saveReport, jsonOutput)
	} else {
		logger.Fatal("Cannot compare a Helm chart with a Docker image. Please provide two Helm charts or two Docker images.")
	}
}

func isHelmChart(ref string) bool {
	// This is a simple heuristic. You might want to improve this logic.
	return strings.Contains(ref, "/") && strings.Contains(ref, "@")
}

func scanSingleImage(imageURL string, saveReport bool, jsonOutput bool) {
	logger.Infof("Scanning image: %s", imageURL)
	result, err := imageScan.ScanImage(imageURL)
	if err != nil {
		logger.Errorf("Error scanning image: %v", err)
		return
	}

	// Generate and handle the report
	report := imageScan.GenerateReport(&imageScan.ImageComparisonReport{
		Image2: result,
	}, jsonOutput, saveReport)

	// Print to console
	fmt.Println(report)
}

func scanSingleHelmChart(chartRef string, saveReport bool, jsonOutput bool) {
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

	// Generate and handle the report
	report := helmscan.GenerateReport(helmscan.HelmComparison{
		After: result,
	}, jsonOutput, saveReport)

	// Print to console
	fmt.Println(report)
}

func compareHelmCharts(chartRef1, chartRef2 string, saveReport bool, jsonOutput bool) {
	parts1 := strings.Split(chartRef1, "@")
	parts2 := strings.Split(chartRef2, "@")
	if len(parts1) != 2 || len(parts2) != 2 {
		logger.Fatalf("Invalid Helm chart reference(s). Expected format: repo/chart@version")
	}

	logger.Infof("Comparing Helm charts: %s and %s", chartRef1, chartRef2)

	// Scan each chart
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
	report := helmscan.GenerateReport(comparison, jsonOutput, saveReport)

	// Print to console
	//fmt.Println(report)

	// Save to file
	err = reports.SaveToFile(report, "helm_comparison_report.md")
	if err != nil {
		log.Fatalf("Error saving report: %v", err)
	}

}

func compareImages(imageURL1, imageURL2 string, saveReport bool, jsonOutput bool) {
	if imageURL1 == "" || imageURL2 == "" {
		fmt.Print("Enter the first image URL: ")
		imageURL1 = getUserInput()
		fmt.Print("Enter the second image URL: ")
		imageURL2 = getUserInput()
	}

	// Scan both images
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

	// Compare the scans
	comparison := imageScan.CompareScans(scan1, scan2)
	report := imageScan.GenerateReport(comparison, jsonOutput, saveReport)

	// Print to console
	fmt.Println(report)

	// Save to file if requested
	if saveReport {
		ext := ".md"
		if jsonOutput {
			ext = ".json"
		}
		filename := fmt.Sprintf("image_comparison_%s_%s%s",
			reports.CreateSafeFileName(imageURL1),
			reports.CreateSafeFileName(imageURL2),
			ext)
		err = reports.SaveToFile(report, filename)
		if err != nil {
			logger.Errorf("Error saving report: %v", err)
		}
	}
}

func ensureWorkingFilesDir() error {
	return os.MkdirAll("working-files", os.ModePerm)
}
