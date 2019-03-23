package analyzers

import "testing"

func TestParseAccessLogLine(t *testing.T) {
	got, err := parseAccessLogLine(`10.0.0.1 - - [21/Mar/2019:21:59:22 +0100] "GET / HTTP/1.1" 200 10001 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/65.0"`)
	if err != nil {
		t.Fatalf("Unexpected error : %v", err)
	}

	expected := &AccessLogInfo{
		ip:     "10.0.0.1",
		method: "GET",
		uri:    "/",
		status: 200,
	}

	if got.ip != expected.ip {
		t.Errorf("Expected IP to be %s. Got %s", expected.ip, got.ip)
	}
	if got.method != expected.method {
		t.Errorf("Expected method to be %s. Got %s", expected.method, got.method)
	}
	if got.uri != expected.uri {
		t.Errorf("Expected URI to be %s. Got %s", expected.uri, got.uri)
	}
	if got.status != expected.status {
		t.Errorf("Expected status to be %d. Got %d", expected.status, got.status)
	}
}

func TestParseVhostFromFilename(t *testing.T) {
	tests := []struct {
		given    string
		expected string
	}{
		{"access.log", "main"},
		{"access_vhost.log", "vhost"},
		{"access_long_vhost.log", "long_vhost"},
		{"ssl_access.log", "main"},
		{"ssl_access_vhost.log", "vhost"},
		{"ssl_access_long_vhost.log", "long_vhost"},
		{"other_vhost.log", "other_vhost"},
	}

	for _, test := range tests {
		got := parseVhostFromFilename(test.given)
		if got != test.expected {
			t.Errorf("parseVhostFromFilename(%s) return %s. Expected %s", test.given, got, test.expected)
		}
	}

}
