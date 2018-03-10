package tlsp

import (
	"strings"
)

// HostQualifies returns true if the hostname alone
// appears eligible for automatic HTTPS. For example,
// localhost, empty hostname, and IP addresses are
// not eligible because we cannot obtain certificates
// for those names.
func HostQualifies(hostname string) bool {
	return hostname != "localhost" && // localhost is ineligible

		// hostname must not be empty
		strings.TrimSpace(hostname) != "" &&

		// must not contain wildcard (*) characters (until CA supports it)
		!strings.Contains(hostname, "*") &&

		// must not start or end with a dot
		!strings.HasPrefix(hostname, ".") &&
		!strings.HasSuffix(hostname, ".")
}
