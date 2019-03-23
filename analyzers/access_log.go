package analyzers

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/hpcloud/tail"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// PrometheusAccessLogSubsystem is the metric subsytem prefix for access_log analysis
const PrometheusAccessLogSubsystem = "access"

type AccessLogInfo struct {
	vhost           string //virtual host who logged the access
	ip, method, uri string // request fields
	status          int    // response status
}

// ExportAccessLogs exposes metrics from apache access logs
func ExportAccessLogs(ctx context.Context, logDir string) error {

	fis, err := ioutil.ReadDir(logDir)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Failed to open dir %s ", logDir))
	}

	labels := []string{"vhost", "ip", "method", "uri", "status"}
	accessLogCounter := promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusAccessLogSubsystem,
		Name:      "log",
	}, labels)

	logs := make(chan *AccessLogInfo)

	wg := sync.WaitGroup{}

	for _, fi := range fis {
		if !fi.IsDir() {
			continue
		}
		if strings.HasPrefix(fi.Name(), "error") || strings.HasPrefix(fi.Name(), "ssl_error") || !strings.HasSuffix(fi.Name(), ".log") {
			logrus.WithField("filename", fi.Name()).Debugln("Skipping file")
			continue
		}

		wg.Add(1)
		go func(filename string) {
			defer wg.Done()
			if err := analyseLogFile(ctx, filepath.Join(logDir, filename), logs); err != nil {
				logrus.WithField("filename", filename).WithError(err).Errorln("Could not analyze access_log file")
			}
		}(fi.Name())

	}

	go func() {
		for log := range logs {
			if err := incrementCounterValue(accessLogCounter, []string{log.vhost, log.ip, log.method, log.uri, strconv.Itoa(log.status)}, 1); err != nil {
				logrus.WithField("accessLogLine", log).WithError(err).Errorln("Failed to count line")
			}
		}
	}()

	// Make sure to close th channel once the context is done
	go func() {
		<-ctx.Done()
		wg.Wait()
		close(logs)
	}()

	return nil
}

func analyseLogFile(ctx context.Context, fileName string, logs chan<- *AccessLogInfo) error {
	log := logrus.WithField("logfile", filepath.Base(fileName))
	t, err := tail.TailFile(fileName, tail.Config{
		Follow:   true,
		ReOpen:   true,
		Location: &tail.SeekInfo{Offset: 0, Whence: os.SEEK_END},
	})
	if err != nil {
		return errors.Wrap(err, "Failed to open log file")
	}
	vhost := parseVhostFromFilename(filepath.Base(fileName))

	for {
		select {
		case <-ctx.Done():
			return nil
		case line := <-t.Lines:
			if line == nil || line.Err != nil {
				continue
			}
			info, err := parseAccessLogLine(line.Text)
			if err != nil {
				log.WithError(err).Debugln("Ignoring line")
				continue
			}
			info.vhost = vhost
			logs <- info
		}
	}
}

func parseVhostFromFilename(filename string) string {
	if filename == "access.log" || filename == "ssl_access.log" {
		return "main"
	}
	if strings.HasPrefix(filename, "access_") {
		return filename[7 : len(filename)-4] // trim "access_" and ".log"
	}
	if strings.HasPrefix(filename, "ssl_access_") {
		return filename[11 : len(filename)-4] // trim "ssl_access_" and ".log"
	}
	return strings.TrimSuffix(filename, ".log")

}

// AccessLogRE can parse apache access log in Combined Log Frrmat
var AccessLogRE = regexp.MustCompile("([\\d]+\\.[\\d]+\\.[\\d]+\\.[\\d]+) [\\w-]+ [\\w-]+ \\[.*\\] \"([A-Z]+) ([^\\s]+) [^\\s]+\" ([\\d]+).*")

func parseAccessLogLine(line string) (*AccessLogInfo, error) {
	if AccessLogRE.MatchString(line) {
		parts := AccessLogRE.FindStringSubmatch(line)
		accessLogInfo := &AccessLogInfo{
			ip:     parts[1],
			method: parts[2],
			uri:    parts[3],
		}
		status := parts[4]
		s, err := strconv.Atoi(status)
		if err != nil {
			return nil, errors.New("Failed to parse response status from line")
		}
		accessLogInfo.status = s
		return accessLogInfo, nil
	}
	return nil, errors.New("Line did not match accesslog format")
}
