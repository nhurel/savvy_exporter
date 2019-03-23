package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nhurel/savvy_exporter/analyzers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {

	var enableProcess = flag.Bool("process-enable", true, "Enable processes metrics")
	var enableAuth = flag.Bool("auth-enable", true, "Enable auth logs metrics")
	var enableAccessLog = flag.Bool("access-log-enable", true, "Enable access logs metrics")
	var processScanInterval = flag.Duration("process-frequency", 5*time.Second, "Processes scan interval")
	var authIgnoreCron = flag.Bool("auth-ignore-cron", false, "Skip cron metrics")
	var accessLogDir = flag.String("acces-log-dir", "/var/log/apache2", "Log dir where access logs are stored")
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
		analyzers.ExportProcesses(ctx, *processScanInterval)
	}
	if *enableAuth {
		analyzers.ExportAuth(ctx, *authIgnoreCron)
	}

	if *enableAccessLog {
		if err := analyzers.ExportAccessLogs(ctx, *accessLogDir); err != nil {
			log.Fatalln(err)
		}
	}

	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(":19098", nil))

	// TODO version
	//TODO : apache metrics
	//TODO : fail2ban metrics
}
