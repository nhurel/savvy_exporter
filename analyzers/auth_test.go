package analyzers

import (
	"testing"

	"github.com/pkg/errors"
)

func TestParseAuthLine(t *testing.T) {

	var tests = []struct {
		line        string
		ignoreCron  bool
		expectedErr error
		expected    *AuthInfo
	}{
		{
			line:       "Mar 21 23:04:01 servername CRON[32490]: pam_unix(cron:session): session opened for user nobody by (uid=65534)",
			ignoreCron: false,
			expected:   &AuthInfo{success: true, username: "nobody", authType: "cron"},
		},
		{
			line:        "Mar 21 23:04:01 servername CRON[32490]: pam_unix(cron:session): session opened for user nobody by (uid=65534)",
			ignoreCron:  true,
			expectedErr: errors.New("Line did not match any known pattern"),
		},
		{
			line:     "Mar 21 22:47:37 servername sshd[29367]: Invalid user shop1 from 139.59.82.59",
			expected: &AuthInfo{success: false, username: "shop1", authType: "ssh"},
		},
		{
			line:       "Mar 21 20:26:03 servername sshd[7033]: Accepted publickey for alice from 10.0.0.1 port 51568 ssh2: RSA ...",
			ignoreCron: false,
			expected:   &AuthInfo{success: true, username: "alice", authType: "ssh"},
		},
		{
			line:       "Mar 21 22:19:18 servername sudo: pam_unix(sudo:session): session opened for user root by alice(uid=0)",
			ignoreCron: false,
			expected:   &AuthInfo{success: true, username: "alice", authType: "sudo"},
		},
		{
			line:       "Mar 21 22:38:45 servername sudo: pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/1 ruser=nathan rhost=  user=nathan",
			ignoreCron: false,
			expected:   &AuthInfo{success: false, username: "alice", authType: "sudo"},
		},
	}

	for _, test := range tests {
		got, err := parseAuthLine(test.line, test.ignoreCron)
		if (err == nil) != (test.expectedErr == nil) {
			t.Errorf("Unexpected result ! expected error %v - got %v", test.expectedErr, err)
		}
		if err != nil && err.Error() != test.expectedErr.Error() {
			t.Errorf("Expected error to be %v but got %v", test.expectedErr, err)
		}
		compareAuthInfo(t, test.expected, got)
	}
}

func compareAuthInfo(t *testing.T, expected, got *AuthInfo) {
	if (expected == nil) != (got == nil) {
		t.Errorf("Unexpected result ! expected %+v - got %+v", expected, got)
	}
	if expected != nil {
		if expected.success != got.success {
			t.Errorf("Expected authInfo.success to be %t but got %t", expected.success, got.success)
		}
		if expected.username != got.username {
			t.Errorf("Expected authInfo.username to be %s but got %s", expected.username, got.username)
		}
		if expected.authType != got.authType {
			t.Errorf("Expected authInfo.authType to be %s but got %s", expected.authType, got.authType)
		}
	}
}
