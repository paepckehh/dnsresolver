// package dnsresolver
package dnsresolver

// import
import (
	"os"
)

// const
const (
	_ping               = "in-addr.arpa"
	_resolvconf         = "/etc/resolv.conf"
	_reverseIP4Suffix   = ".in-addr.arpa"
	_whitespace         = ' '
	_tab                = '\t'
	_tabSep             = "\t"
	_lineFeed           = '\n'
	_empty              = ""
	_linefeed           = "\n"
	_sep                = "\t"
	_dot                = "."
	_dotRune            = '.'
	_tcptls             = "tcp-tls"
	_tcp                = "tcp"
	_udp                = "udp"
	_six                = "6"
	_four               = "4"
	_dns                = "DNS "
	_policyhost         = "policy host:"
	_rfail              = "FAIL "
	_noAnswer           = "no answer"
	_errLookup          = " lookup failed : "
	_errUnsupportedType = "unsupported Type: "
	_errKeyPin          = "[dnsinfo] [tls keypin verification failed] "
	_errReverseAnswer   = "[dnsinfo] [reverse-lookup] invalid response from server "
	_errReverseLookup   = "[dnsinfo] [reverse-lookup] not a valid IP4 address: "
)

//
// LITTLE HELPER
//

// fqdn ...
// func fqdn(name string) string {
// 	l := len(name)
// 	if l > 0 {
// 		last := name[l-1]
// 		if last == _dotRune {
// 			return name
// 		}
// 		return name + _dot
// 	}
// 	return "empty.hostname"
// }

// isFile ...
func isFile(filename string) bool {
	fi, err := os.Lstat(filename)
	if err != nil {
		return false
	}
	return fi.Mode().IsRegular()
}

// removeEmptyLines
func removeEmptyLines(textBlock string) string {
	in := []byte(textBlock)
	size, void, buff, clean := len(in), true, []byte{}, []byte{}
	for i := 0; i < size; i++ {
		switch in[i] {
		case _whitespace, _tab:
			if void {
				buff = append(buff, in[i])
				continue
			}
			clean = append(clean, in[i])
		case _lineFeed:
			if void {
				buff = []byte{}
				continue
			}
			void = true
			clean = append(clean, _lineFeed)
		default:
			if void {
				clean = append(clean, buff...)
				buff = []byte{}
			}
			clean = append(clean, in[i])
			void = false
		}
	}
	return string(clean)
}
