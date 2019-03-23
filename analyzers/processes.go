package analyzers

import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// PrometheusProcessesSubsystem is the metric subsytem prefix for processes
const PrometheusProcessesSubsystem = "processes"

//ProcessInfo descibes all info to expose about a process
type ProcessInfo struct {
	pidLabel, cmdlineLabel, cmdLabel, stateLabel string // labels
	utime, stime                                 int    // cpu times
	vmsize, resident, shared, percent            int    // memory
}

var totalMemory int

// ExportProcesses starts watching the processes to export their metrics
func ExportProcesses(ctx context.Context, freq time.Duration) error {
	logrus.Debugf("Exporting processes metrics every %s", freq)
	var err error
	totalMemory, err = parseMeminfo("/proc/meminfo")
	if err != nil {
		return errors.Wrap(err, "Could not read memory info")
	}
	logrus.WithField("totalMemory", totalMemory).Debugln("Print total memory")

	var metricLabels = []string{"pid", "cmdline", "cmd", "state"}

	var vmsizeVector = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusProcessesSubsystem,
		Name:      "vmsize",
		Help:      "Total program size",
	}, metricLabels)
	var residentVector = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusProcessesSubsystem,
		Name:      "resident",
		Help:      "resident set size (VmRSS)",
	}, metricLabels)
	var memPercentVector = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusProcessesSubsystem,
		Name:      "mem_percent_usage",
		Help:      "Memory Percent usage",
	}, metricLabels)
	var sharedVector = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusProcessesSubsystem,
		Name:      "shared",
		Help:      "Shared memory",
	}, metricLabels)

	var utimeVector = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusProcessesSubsystem,
		Name:      "utime",
		Help:      "Amount of time process has been scheduled in user mode",
	}, metricLabels)

	var stimeVector = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusProcessesSubsystem,
		Name:      "stime",
		Help:      "Amount of time process has been scheduled in kernel mode",
	}, metricLabels)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.Tick(freq):
				processes, err := scanProcesses("/proc")
				if err != nil {
					logrus.WithError(err).Errorln("Could not scan processes")
				} else {
					exposeMetrics(processes, vmsizeVector, residentVector, memPercentVector, sharedVector, utimeVector, stimeVector)
				}
			}
		}
	}()
	return nil
}

func scanProcesses(processPath string) (<-chan *ProcessInfo, error) {
	fis, err := ioutil.ReadDir(processPath)
	if err != nil {
		return nil, errors.Wrap(err, "Could not open /proc")
	}

	processes := make(chan *ProcessInfo)

	go func() {
		wg := sync.WaitGroup{}

		for _, fi := range fis {
			wg.Add(1)
			go func(fi os.FileInfo) {
				defer wg.Done()
				analyzeProcess(processPath, fi, processes)
			}(fi)
		}

		wg.Wait()
		close(processes)
	}()

	return processes, nil
}

func exposeMetrics(processes <-chan *ProcessInfo, vmsizeVector, residentVector, memPercentVector, sharedVector, utimeVector, stimeVector *prometheus.GaugeVec) {
	for process := range processes {
		labelValues := []string{process.pidLabel, process.cmdlineLabel, process.cmdLabel, process.stateLabel}
		log := logrus.WithField("pid", process.pidLabel)
		if err := setGaugeValue(vmsizeVector, labelValues, process.vmsize); err != nil {
			log.WithField("gauge", "vmsize").WithError(err).WithField("labels", labelValues).Errorln("Could not report value")
		}
		if err := setGaugeValue(residentVector, labelValues, process.resident); err != nil {
			log.WithField("gauge", "resident").WithError(err).WithField("labels", labelValues).Errorln("Could not report value")
		}
		if err := setGaugeValue(sharedVector, labelValues, process.shared); err != nil {
			log.WithField("gauge", "shared").WithError(err).WithField("labels", labelValues).Errorln("Could not report value")
		}
		if err := setGaugeValue(memPercentVector, labelValues, process.percent); err != nil {
			log.WithField("gauge", "mem_percent_usage").WithError(err).WithField("labels", labelValues).Errorln("Could not report value")
		}
		if err := setGaugeValue(utimeVector, labelValues, process.utime); err != nil {
			log.WithField("gauge", "utime").WithError(err).WithField("labels", labelValues).Errorln("Could not report value")
		}
		if err := setGaugeValue(stimeVector, labelValues, process.stime); err != nil {
			log.WithField("gauge", "stime").WithError(err).WithField("labels", labelValues).Errorln("Could not report value")
		}
	}
}

func analyzeProcess(processPath string, process os.FileInfo, out chan<- *ProcessInfo) {

	if !process.IsDir() {
		return
	}

	processid := filepath.Base(process.Name())
	var pid int
	var err error
	if pid, err = strconv.Atoi(processid); err != nil {
		return
	}

	var pidLabel, cmdlineLabel, cmdLabel, stateLabel string
	pidLabel = processid

	log := logrus.WithField("pid", pid)
	proc := filepath.Join(processPath, process.Name())
	f, err := os.Open(proc)
	defer f.Close()
	if err != nil {
		log.WithError(err).Errorln("Could not inspect process")
		return
	}
	cmdline, err := ioutil.ReadFile(filepath.Join(proc, "cmdline"))
	if err != nil {
		log.WithError(err).Warnf("Could not read cmdline")
		cmdline = []byte{}
	}
	cmdlineLabel = string(cmdline)

	//TODO /proc/pid/io to get read_bytes/writes_bytes. This requires to store previous value to be able to compute read/write per sec. This can only be read as root ?

	statBytes, err := ioutil.ReadFile(filepath.Join(proc, "stat"))
	var utime, stime int
	if err != nil {
		log.WithError(err).Errorln("Could not read stat file")
		return
	} else {
		cmdLabel, stateLabel, utime, stime, err = parseStatContent(string(statBytes))
		if err != nil {
			log.WithError(err).Errorln("Stat file was not parsed correctly")
			return
		}
	}

	statmBytes, err := ioutil.ReadFile(filepath.Join(proc, "statm"))
	var vmsize, resident, shared int
	if err != nil {
		log.WithError(err).Errorln("Could not read statm file")
		return
	} else {
		vmsize, resident, shared, err = parseStatmContent(string(statmBytes))
		if err != nil {
			log.WithError(err).Errorln("Statm file was not parsed correctly")
			return
		}
	}
	percent := 100 * resident / totalMemory

	out <- &ProcessInfo{
		pidLabel:     pidLabel,
		cmdlineLabel: cmdlineLabel,
		cmdLabel:     cmdLabel,
		stateLabel:   stateLabel,
		utime:        utime,
		stime:        stime,
		vmsize:       vmsize,
		resident:     resident,
		shared:       shared,
		percent:      percent,
	}
}

func parseStatContent(stat string) (cmd string, state string, utime int, stime int, err error) {
	statParts := strings.Split(stat, " ")
	if len(statParts) < 15 {
		err = fmt.Errorf("stat doesn't contain 15 fields, only %d", len(statParts))
		return
	}
	cmd = statParts[1]
	cmd = string(cmd[1 : len(cmd)-1]) // remove surrounding parenthesis

	switch statParts[2] {
	case "R":
		state = "Running"
	case "S":
		state = "Sleeping"
	case "D":
		state = "Waiting"
	case "Z":
		state = "Zombie"
	case "T":
		state = "Stopped"
	case "t":
		state = "Tracing"
	case "X":
		state = "Dead"
	case "x":
		state = "Dead"
	case "K":
		state = "Wakekill"
	case "W":
		state = "Waking"
	case "P":
		state = "Parked"
	}

	var convErr error
	utime, convErr = strconv.Atoi(statParts[13])
	if convErr != nil {
		err = fmt.Errorf("Bad format utime : %v", convErr)
	}
	stime, convErr = strconv.Atoi(statParts[14])
	if convErr != nil {
		err = fmt.Errorf("Bad format stime : %v", convErr)
	}
	return
}

// Meminfo in statm are in number of pages. Needs to multiply by page size to get value in bytes
var pageSize = os.Getpagesize()

func parseStatmContent(statm string) (vmsize, resident, shared int, err error) {
	statmParts := strings.Split(statm, " ")
	if len(statmParts) != 7 {
		err = fmt.Errorf("statm doesn't contain 7 fields, only %d", len(statmParts))
		return
	}
	var convErr error
	vmsize, convErr = strconv.Atoi(statmParts[0])
	if convErr != nil {
		err = fmt.Errorf("Bad format vmsize : %v", convErr)
	}
	vmsize *= pageSize
	resident, convErr = strconv.Atoi(statmParts[1])
	if convErr != nil {
		err = fmt.Errorf("Bad format resident : %v", convErr)
	}
	resident *= pageSize
	shared, convErr = strconv.Atoi(statmParts[2])
	if convErr != nil {
		err = fmt.Errorf("Bad format shared : %v", convErr)
	}
	shared *= pageSize
	return
}

var MeminfoRE = regexp.MustCompile("MemTotal:\\s+(\\d+)\\s*([a-zA-Z]+)")

func parseMeminfo(meminfoPath string) (int, error) {
	file, err := os.Open(meminfoPath)
	defer file.Close()
	if err != nil {
		return 0, err
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if parts := MeminfoRE.FindStringSubmatch(scanner.Text()); parts != nil {
			totalString := parts[1]
			total, err := strconv.Atoi(totalString)
			if err != nil {
				return 0, err
			}
			if parts[2] != "kB" {
				return 0, fmt.Errorf("Unsupported memory unit : %s", parts[2])
			}
			return total * 1024, nil
		}
	}
	return 0, errors.New("Could not find MemTotal in /proc/meminfo")
}
