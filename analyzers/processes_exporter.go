package analyzers

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
)

// PrometheusProcessesSubsystem is the metric subsytem prefix for processes
const PrometheusProcessesSubsystem = "processes"

// ProcessesExporter consumes ProcessInfo and export them to prometheus
type ProcessesExporter struct {
	vmsizeVector, residentVector   *prometheus.GaugeVec
	memPercentVector, sharedVector *prometheus.GaugeVec
	utimeVector, stimeVector       *prometheus.GaugeVec
}

// Consume reads process info from a channel and expose them to prometheus
func (pe *ProcessesExporter) Consume(processes <-chan *ProcessInfo) {
	for process := range processes {
		pe.Export(process)
	}
}

// Export exposes a processInfo to prometheus
func (pe *ProcessesExporter) Export(process *ProcessInfo) {
	labelValues := []string{process.pidLabel, process.cmdlineLabel, process.cmdLabel}
	log := logrus.WithField("pid", process.pidLabel)
	if err := setGaugeValue(pe.vmsizeVector, labelValues, process.vmsize); err != nil {
		log.WithField("gauge", "vmsize").WithError(err).WithField("labels", labelValues).Errorln("Could not report value")
	}
	if err := setGaugeValue(pe.residentVector, labelValues, process.resident); err != nil {
		log.WithField("gauge", "resident").WithError(err).WithField("labels", labelValues).Errorln("Could not report value")
	}
	if err := setGaugeValue(pe.sharedVector, labelValues, process.shared); err != nil {
		log.WithField("gauge", "shared").WithError(err).WithField("labels", labelValues).Errorln("Could not report value")
	}
	if err := setGaugeValue(pe.memPercentVector, labelValues, process.percent); err != nil {
		log.WithField("gauge", "mem_percent_usage").WithError(err).WithField("labels", labelValues).Errorln("Could not report value")
	}
	if err := setGaugeValue(pe.utimeVector, labelValues, process.utime); err != nil {
		log.WithField("gauge", "utime").WithError(err).WithField("labels", labelValues).Errorln("Could not report value")
	}
	if err := setGaugeValue(pe.stimeVector, labelValues, process.stime); err != nil {
		log.WithField("gauge", "stime").WithError(err).WithField("labels", labelValues).Errorln("Could not report value")
	}
}

// NewProcessesExporter must be called only once as it creates and register named gauges to prometheus registry
func NewProcessesExporter() *ProcessesExporter {
	var metricLabels = []string{"pid", "cmdline", "cmd"}
	return &ProcessesExporter{
		vmsizeVector: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: PrometheusNamespace,
			Subsystem: PrometheusProcessesSubsystem,
			Name:      "vmsize",
			Help:      "Total program size",
		}, metricLabels),
		residentVector: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: PrometheusNamespace,
			Subsystem: PrometheusProcessesSubsystem,
			Name:      "resident",
			Help:      "resident set size (VmRSS)",
		}, metricLabels),
		memPercentVector: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: PrometheusNamespace,
			Subsystem: PrometheusProcessesSubsystem,
			Name:      "mem_percent_usage",
			Help:      "Memory Percent usage",
		}, metricLabels),
		sharedVector: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: PrometheusNamespace,
			Subsystem: PrometheusProcessesSubsystem,
			Name:      "shared",
			Help:      "Shared memory",
		}, metricLabels),

		utimeVector: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: PrometheusNamespace,
			Subsystem: PrometheusProcessesSubsystem,
			Name:      "utime",
			Help:      "Amount of time process has been scheduled in user mode",
		}, metricLabels),

		stimeVector: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: PrometheusNamespace,
			Subsystem: PrometheusProcessesSubsystem,
			Name:      "stime",
			Help:      "Amount of time process has been scheduled in kernel mode",
		}, metricLabels),
	}
}
