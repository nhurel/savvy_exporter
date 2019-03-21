package analyzers

import (
	"strings"
	"testing"
)

func TestScanProcesses(t *testing.T) {
	processes, err := scanProcesses("./testdata/proc")

	if err != nil {
		t.Fatal(err)
	}

	nbProcesses := 0
	for process := range processes {
		nbProcesses++
		if process.cmdLabel != "grafana-server" {
			t.Errorf("Expected cmdLabel to be '%s' but got '%s'", "grafana-server", process.cmdLabel)
		}
		if !strings.HasPrefix(process.cmdlineLabel, "/usr/sbin/grafana-server") {
			t.Errorf("Expected cmdlineLabel to start with '%s' but got '%s'", "/usr/sbin/grafana-server", process.cmdlineLabel)
		}
		if process.pidLabel != "1234" {
			t.Errorf("Expected pidLabel to be '%s' but got '%s'", "1234", process.pidLabel)
		}
		if process.stateLabel != "Sleeping" {
			t.Errorf("Expected stateLabel to be '%s' but got '%s'", "Sleeping", process.stateLabel)
		}
		if process.resident != 11603 {
			t.Errorf("Expected resident to be '%d' but got '%d'", 11603, process.resident)
		}
		if process.shared != 6664 {
			t.Errorf("Expected shared to be '%d' but got '%d'", 6664, process.shared)
		}
		if process.vmsize != 315224 {
			t.Errorf("Expected vmsize to be '%d' but got '%d'", 315224, process.vmsize)
		}
		if process.utime != 2850 {
			t.Errorf("Expected utime to be '%d' but got '%d'", 2850, process.utime)
		}
		if process.stime != 634 {
			t.Errorf("Expected stime to be '%d' but got '%d'", 634, process.stime)
		}
	}
	if nbProcesses != 1 {
		t.Errorf("Expected ScanProcesses to scan 1 process but %d were inspected", nbProcesses)
	}
}
