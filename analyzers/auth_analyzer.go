package analyzers

import (
	"context"
	"os"
	"regexp"
	"strings"

	"github.com/hpcloud/tail"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	SshAuthType  = "ssh"
	CronAuthType = "cron"
	SudoAuthType = "sudo"
)

type AuthInfo struct {
	authType string // kind of auth : sshd, cron, sudo
	success  bool
	username string
	ip       string
}

// ExportAuth exposes promethus metric about login attempts
func ExportAuth(ctx context.Context, ignoreCron, withCountry bool) error {

	t, err := tail.TailFile("/var/log/auth.log", tail.Config{
		Location: &tail.SeekInfo{Offset: 0, Whence: os.SEEK_END},
		Follow:   true,
		ReOpen:   true,
		Logger:   tail.DiscardingLogger})
	if err != nil {
		return errors.Wrap(err, "Fail to tail /var/log/auth.log")
	}

	exporter := NewAuthExporter(withCountry)

	go func() {
		for {
			select {
			case line := <-t.Lines:
				if line == nil || line.Err != nil {
					continue
				}
				log := logrus.WithField("line", line)
				log.Debugln("Parsing new auth log")
				authLine, err := parseAuthLine(line.Text, ignoreCron)
				if err == nil {
					if err := exporter.Export(authLine); err != nil {
						log.WithField("authLine", authLine).WithError(err).Errorln("Failed to count line")
					}
				} else {
					log.WithError(err).Warnln("Failed to parse auth line")
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}

// Mar 21 23:04:01 servername CRON[32490]: pam_unix(cron:session): session opened for user nobody by (uid=65534)

var CronRE = regexp.MustCompile(".* CRON\\[[\\d]+\\]: pam_unix\\(cron:session\\): session opened for user ([\\w]+)\\s+.*")

// Mar 21 22:47:37 servername sshd[29367]: Invalid user shop1 from 139.59.82.59
// Mar 21 20:26:03 servername sshd[7033]: Accepted publickey for alice from 10.0.0.1 port 51568 ssh2: RSA ...

var SshRE = regexp.MustCompile(".* sshd\\[[\\d]+\\]:\\s+(Invalid user |Accepted publickey for )([\\w]+)\\s+from\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+).*")

// Mar 21 22:19:18 servername sudo: pam_unix(sudo:session): session opened for user root by alice(uid=0)
// Mar 21 22:38:45 servername sudo: pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/1 ruser=alice rhost=  user=alice
var SudoRE = regexp.MustCompile(".* sudo:\\s+pam_unix\\(sudo:.+\\):\\s+(session opened|authentication failure;).*(by ([\\w]+)\\(uid.*|logname=([\\w]+)\\s+)")

func parseAuthLine(line string, ignoreCron bool) (*AuthInfo, error) {
	var authInfo *AuthInfo
	if SudoRE.MatchString(line) {
		groups := SudoRE.FindStringSubmatch(line)
		authInfo = &AuthInfo{
			authType: SudoAuthType,
			success:  (groups[1] == "session opened"),
		}
		if authInfo.success {
			authInfo.username = groups[3]
		} else {
			authInfo.username = groups[4]
		}
		return authInfo, nil
	}

	if SshRE.MatchString(line) {
		groups := SshRE.FindStringSubmatch(line)
		authInfo = &AuthInfo{
			authType: SshAuthType,
			success:  strings.HasPrefix(groups[1], "Accepted"),
			username: groups[2],
			ip:       groups[3],
		}
		return authInfo, nil
	}

	if !ignoreCron && CronRE.MatchString(line) {
		groups := CronRE.FindStringSubmatch(line)
		authInfo = &AuthInfo{
			authType: CronAuthType,
			success:  true,
			username: groups[1],
		}
		return authInfo, nil
	}

	return nil, errors.New("Line did not match any known pattern")
}
