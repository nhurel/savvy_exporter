package analyzers

import (
	"strings"
	"testing"
)

func TestScanProcesses(t *testing.T) {
	totalMemory = 16147176 * 1024
	pageSize = 4096
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
		if process.resident != 47525888 {
			t.Errorf("Expected resident to be '%d' but got '%d'", 47525888, process.resident)
		}
		if process.percent != 0 {
			t.Errorf("Expected percent to be '%d' but got '%d'", 0, process.percent)
		}
		if process.shared != 27295744 {
			t.Errorf("Expected shared to be '%d' but got '%d'", 27295744, process.shared)
		}
		if process.vmsize != 1291157504 {
			t.Errorf("Expected vmsize to be '%d' but got '%d'", 1291157504, process.vmsize)
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

func TestParseMemInfo(t *testing.T) {
	got, err := parseMeminfo("testdata/meminfo")
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}
	if got != 16147176*1024 {
		t.Errorf("Expected memory to be %d but got %d", 16534708224, got)
	}
}
