package analyzers

import (
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

const PrometheusNamespace = "savvy"

func setGaugeValue(gaugeVector *prometheus.GaugeVec, labels []string, value int) error {
	observer, err := gaugeVector.GetMetricWithLabelValues(labels...)
	if err != nil {
		return err
	}
	observer.Set(float64(value))
	return nil
}

func incrementCounterValue(counterVector *prometheus.CounterVec, labels []string, incr int) error {
	if incr < 0 {
		return errors.New("increment must be positive")
	}
	observer, err := counterVector.GetMetricWithLabelValues(labels...)
	if err != nil {
		return err
	}
	observer.Add(float64(incr))
	return nil
}
