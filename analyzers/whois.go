package analyzers

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	whoisResolver = []string{
		"whois.ripe.net:43",
		"whois.apnic.net:43",
		"whois.arin.net:43",
		"whois.iana.org:43",
		"whois.lacnic.net:43",
	}

	CountryCodeNotFound = errors.New("Could not find country code")
)

type WhoisQuerier struct {
	resolvers []string
}

func NewWhoisQuerier(resolvers ...string) *WhoisQuerier {
	rslv := resolvers
	if len(rslv) == 0 {
		rslv = whoisResolver
	}
	wq := &WhoisQuerier{resolvers: rslv}
	return wq
}

func (wq *WhoisQuerier) IPToCountryCode(ipaddress string) (string, error) {
	log := logrus.WithField("ip", ipaddress)
	log.Debugln("Searching country code")

	for _, resolver := range wq.resolvers {
		cc, err := resolveCountryCode(ipaddress, resolver)
		if err == nil {
			return cc, nil
		}
		if err != CountryCodeNotFound {
			log.WithField("resolver", resolver).WithError(err).Warnln("Error happened while searching country code")
		}
	}

	return "", CountryCodeNotFound
}

func resolveCountryCode(ipaddress, resolver string) (string, error) {
	log := logrus.WithFields(logrus.Fields{"ip": ipaddress, "resolver": resolver})
	conn, err := net.DialTimeout("tcp", resolver, 1*time.Second)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to connect to resolver %s", resolver)
	}
	defer conn.Close()
	if _, err = fmt.Fprintln(conn, ipaddress); err != nil {
		return "", errors.Wrapf(err, "Failed to query whois resolver %s", resolver)
	}
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		log.WithField("line", line).Debugln("Parsing whois line")
		if strings.HasPrefix(line, "country:") {
			return line[len(line)-2:], nil
		}
	}
	log.Debugln("Could not find country code")
	return "", CountryCodeNotFound
}
