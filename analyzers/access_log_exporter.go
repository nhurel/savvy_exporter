package analyzers

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
)

// PrometheusAccessLogSubsystem is the metric subsytem prefix for access_log analysis
const PrometheusAccessLogSubsystem = "access"

type AccessLogExporter struct {
	counter     *prometheus.CounterVec
	withCountry bool
	wq          *WhoisQuerier
}

func NewAccessLogExporter(withCountry bool) *AccessLogExporter {
	labels := []string{"vhost", "method", "uri", "status"}
	var wq *WhoisQuerier
	if withCountry {
		labels = append(labels, "country")
		wq = NewWhoisQuerier()
	}
	accessLogCounter := promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusAccessLogSubsystem,
		Name:      "log",
	}, labels)

	return &AccessLogExporter{
		counter:     accessLogCounter,
		withCountry: withCountry,
		wq:          wq,
	}
}

func (ale *AccessLogExporter) Export(log *AccessLogInfo) error {
	values := []string{log.vhost, log.method, log.uri, strconv.Itoa(log.status)}

	if ale.withCountry {
		country, err := ale.wq.IPToCountryCode(log.ip)
		if err != nil {
			logrus.WithError(err).Errorln("Failed to enrich log with country")
		}
		values = append(values, country)
	}

	return incrementCounterValue(ale.counter, values, 1)
}
