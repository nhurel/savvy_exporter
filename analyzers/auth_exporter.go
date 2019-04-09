package analyzers

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
)

// PrometheusAuthSubsystem is the metric subsytem prefix for auth.log analysis
const PrometheusAuthSubsystem = "auth"

type AuthExporter struct {
	counter     *prometheus.CounterVec
	withCountry bool
	wq          *WhoisQuerier
}

func NewAuthExporter(withCountry bool) *AuthExporter {
	var labels = []string{"type", "success", "username"}
	var wq *WhoisQuerier
	if withCountry {
		labels = append(labels, "country")
		wq = NewWhoisQuerier()
	}
	authCounter := promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusAuthSubsystem,
		Name:      "log",
		Help:      "Number of auth attempts",
	}, labels)

	return &AuthExporter{
		counter:     authCounter,
		withCountry: withCountry,
		wq:          wq,
	}
}

func (ae *AuthExporter) Export(authLine *AuthInfo) error {
	values := []string{authLine.authType, strconv.FormatBool(authLine.success), authLine.username}

	if ae.withCountry {
		if authLine.authType == SshAuthType {
			country, err := ae.wq.IPToCountryCode(authLine.ip)
			if err != nil {
				logrus.WithError(err).Errorln("Failed to enrich log with country")
			}
			values = append(values, country)
		} else {
			values = append(values, "")
		}
	}

	return incrementCounterValue(ae.counter, values, 1)
}
