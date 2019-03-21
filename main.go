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

	var processScanInterval = flag.Duration("process-frequency", 5*time.Second, "Processes scan interval")
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

	analyzers.ExportProcesses(context.Background(), *processScanInterval)

	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(":19098", nil))

	// TODO version
	//TODO : apache metrics
	//TODO : fail2ban metrics
	//TODO : /var/log/auth metrics
}
