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
)

//ProcessInfo descibes all info to expose about a process
type ProcessInfo struct {
	pidLabel, cmdlineLabel, cmdLabel, stateLabel string // labels
	utime, stime                                 int    // cpu times
	vmsize, resident, shared, percent            int    // memory
}

type ConsumeProcessesFunc func(<-chan *ProcessInfo)

// ProcessInfoConsumer reads the ProcessInfo sent to a channel
type ProcessInfoConsumer interface {
	Consume(<-chan *ProcessInfo)
}

// ProcessesAnalyzer is the object responsible for getting all ProcessInfo from processes running on a system
type ProcessesAnalyzer struct {
	sync.RWMutex
	PageSize        int             //os page size
	TotalMemory     int             //os total memory
	ProcessPath     string          //path to process dir (default /proc)
	IgnoreStates    map[string]bool //process states to ignore
	MinCPU          int             // min cpu usage to be exported
	Consumer        ProcessInfoConsumer
	cmdlineByPID    map[string]string //cache of process cmdline
	activeProcesses map[string]bool   //keep track of cache entries cmdlineByPID
}

// ExportProcesses starts watching the processes to export their metrics
func (pa *ProcessesAnalyzer) ExportProcesses(ctx context.Context, freq time.Duration) {

	if pa.cmdlineByPID == nil {
		pa.cmdlineByPID = make(map[string]string)
	}
	go func() {
		ticker := time.NewTicker(freq)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pa.cleanState()
				processes, err := pa.scanProcesses()
				if err != nil {
					logrus.WithError(err).Errorln("Could not scan processes")
				} else {
					pa.Consumer.Consume(processes)
				}
			}
		}
	}()
}

// ExportProcesses starts watching the processes to export their metrics
func ExportProcesses(ctx context.Context, freq time.Duration, ignoreStates map[string]bool, minCPU int) error {
	logrus.Debugf("Exporting processes metrics every %s", freq)
	var err error
	processAnalyzer := &ProcessesAnalyzer{
		PageSize:     os.Getpagesize(),
		ProcessPath:  "/proc",
		IgnoreStates: ignoreStates,
		MinCPU:       minCPU,
		Consumer:     NewProcessesExporter(),
	}

	var totalMemory int
	totalMemory, err = parseMeminfo("/proc/meminfo")
	if err != nil {
		return errors.Wrap(err, "Could not read memory info")
	}
	logrus.WithField("totalMemory", totalMemory).Debugln("Print total memory")
	processAnalyzer.TotalMemory = totalMemory

	processAnalyzer.ExportProcesses(ctx, freq)
	return nil
}

func (pa *ProcessesAnalyzer) scanProcesses() (<-chan *ProcessInfo, error) {
	fis, err := ioutil.ReadDir(pa.ProcessPath)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Could not open %s", pa.ProcessPath))
	}

	processes := make(chan *ProcessInfo)

	activeProcesses := make(map[string]bool)

	go func() {
		wg := sync.WaitGroup{}
		for _, fi := range fis {
			wg.Add(1)
			activeProcesses[fi.Name()] = true
			go func(fi os.FileInfo) {
				defer wg.Done()
				pa.analyzeProcess(fi, processes)
			}(fi)
		}
		wg.Wait()
		close(processes)
		pa.Lock()
		defer pa.Unlock()
		pa.activeProcesses = activeProcesses
	}()

	return processes, nil
}

// cleanState clears cmdlineByPID cache according to tracked active pid
func (pa *ProcessesAnalyzer) cleanState() {
	pa.Lock()
	defer pa.Unlock()

	for p := range pa.cmdlineByPID {
		if pa.activeProcesses == nil || !pa.activeProcesses[p] {
			delete(pa.cmdlineByPID, p)
		}
	}
	if pa.cmdlineByPID == nil {
		pa.cmdlineByPID = make(map[string]string)
	}
}

func (pa *ProcessesAnalyzer) getCmdline(pid string) (string, error) {
	pa.RLock()
	if cmdline, found := pa.cmdlineByPID[pid]; found {
		pa.RUnlock()
		return cmdline, nil
	}
	pa.RUnlock()

	cmdline, err := ioutil.ReadFile(filepath.Join(pa.ProcessPath, pid, "cmdline"))
	if err != nil {
		return "", errors.Wrap(err, "Could not read cmdline")
	}
	pa.Lock()
	defer pa.Unlock()
	pa.cmdlineByPID[pid] = string(cmdline)
	return string(cmdline), nil

}

func (pa *ProcessesAnalyzer) analyzeProcess(process os.FileInfo, out chan<- *ProcessInfo) {

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
	proc := filepath.Join(pa.ProcessPath, process.Name())
	f, err := os.Open(proc)
	defer f.Close()
	if err != nil {
		log.WithError(err).Errorln("Could not inspect process")
		return
	}
	cmdlineLabel, err = pa.getCmdline(processid)
	if err != nil {
		log.WithError(err).Warnln("Failed to get command line")
		return
	}

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
		if utime+stime < pa.MinCPU {
			log.WithField("cpu", utime+stime).Debugln("Ignoring process")
			return
		}
	}

	if pa.IgnoreStates[stateLabel] {
		log.WithField("State", stateLabel).Debugln("Ignoring process")
		return
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
	percent := 100 * resident / pa.TotalMemory

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
