package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nhurel/savvy_exporter/analyzers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var Version string

func main() {
	// Display version if asked
	version()

	var enableProcess = flag.Bool("process-enable", true, "Enable processes metrics")
	var enableAuth = flag.Bool("auth-enable", true, "Enable auth logs metrics")
	var enableAccessLog = flag.Bool("access-log-enable", true, "Enable access logs metrics")
	var processScanInterval = flag.Duration("process-frequency", 5*time.Second, "Processes scan interval")
	var authIgnoreCron = flag.Bool("auth-ignore-cron", false, "Skip cron metrics")
	var authIPLoc = flag.Bool("auth-iploc", true, "Enrich metrics with country code associated to ip addresses")
	var accessLogDir = flag.String("access-log-dir", "/var/log/apache2", "Log dir where access logs are stored")
	var accessLogIPLoc = flag.Bool("access-log-iploc", true, "Enrich metrics with country code associated to ip addresses")
	var logLevel = flag.String("log", "info", "log level : debug, info, warn, error")
	flag.Parse()
	switch *logLevel {
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	case "warn":
		logrus.SetLevel(logrus.WarnLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	default:
		log.Fatalf("Unknown log level %s", *logLevel)
	}

	ctx := context.Background()

	if *enableProcess {
		if err := analyzers.ExportProcesses(ctx, *processScanInterval); err != nil {
			log.Fatalln(err)
		}
	}
	if *enableAuth {
		if err := analyzers.ExportAuth(ctx, *authIgnoreCron, *authIPLoc); err != nil {
			log.Fatalln(err)
		}
	}

	if *enableAccessLog {
		if err := analyzers.ExportAccessLogs(ctx, *accessLogDir, *accessLogIPLoc); err != nil {
			log.Fatalln(err)
		}
	}

	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(":19098", nil))

	// TODO version
	//TODO : fail2ban metrics
}

func version() {
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "-v" || os.Args[1] == "version") {
		fmt.Printf("savvy_exporter v%s\n", Version)
		os.Exit(0)
	}
}
