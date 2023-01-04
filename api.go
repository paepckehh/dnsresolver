// package dnsresolver
package dnsresolver

// import
import (
	"crypto/tls"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

//
// SIMPLE API
//

// Lookup ...
func Lookup(hostname string, rType uint16) ([]string, error) {
	return ResolverAuto().resolvePlain(hostname, rType)
}

// LookupIP ...
func LookupIP(hostname string) ([]netip.Addr, error) {
	return ResolverAuto().resolveAddrs(hostname, []uint16{dns.TypeA, dns.TypeAAAA})
}

// LookupIP4 ...
func LookupIP4(hostname string) ([]netip.Addr, error) {
	return ResolverAuto().resolveAddr(hostname, dns.TypeA)
}

// LookupIP6 ...
func LookupIP6(hostname string) ([]netip.Addr, error) {
	return ResolverAuto().resolveAddr(hostname, dns.TypeAAAA)
}

// ReverseLookupIP4 ...
func ReverseLookupIP4(ip4 string) (string, error) {
	return ResolverAuto().reverseIP4(_emptyAddr, ip4)
}

// ReverseLookupIP4Addr ...
func ReverseLookupIP4Addr(ip4Addr netip.Addr) (string, error) {
	return ResolverAuto().reverseIP4(ip4Addr, _empty)
}

// CacheAll ...
func CacheAll(hostname string) {
	_, _ = ResolverAuto().exchangeAll(hostname, false, false, TypeAll)
}

//
// RESOLVER
//

// Resolver ..
type Resolver struct {
	Name string
	// Server server_ip:port
	Server string
	// NoIP4 no dns.srv conn attempt via ip4
	NoIP4 bool
	// NoIP6 no dns.srv conn attempt via ip6
	NoIP6 bool
	// NoUDP no dns.src conn attempt via udp
	NoUDP bool
	// NoTCP no dns.src conn attempt via tcp
	NoTCP bool
	// DoT/TLS enforced, disables TCP & UDP
	DoT bool
	// TLSKeyPin for DoT (optional)
	TLSKeyPin string
	// TLSconfig TLS/DoT settings (optional)
	// when custom tls.Config and TLSKeyPin are enabled a tlsconfig.VerifyConnection
	// function is required (examples, see resolver.go or use tlsConfigPin(TLSKeyPin))
	TLSConfig *tls.Config
	// Timeout ...
	Timeout time.Duration
}

// Answer ...
type Answer struct {
	Raw     map[uint16]string
	Summary map[uint16]string
}

// TypeAll holds all DNS Types (A, AAA, CNAME, MX ...)
var TypeAll []uint16 = rTypeAll()

// ResolverViaProvider ...
func ResolverViaProvider(name string, dot bool) *Resolver {
	return resolverProviderName(name, dot)
}

// ResolverLocalhost ...
func ResolverLocalhost() *Resolver {
	return &Resolver{
		Name:    "localhost",
		Server:  "127.0.0.1:53",
		Timeout: 8 * time.Second,
	}
}

// ResolverResolvConf ...
func ResolverResolvConf() *Resolver {
	c, err := dns.ClientConfigFromFile(_resolvconf)
	if err != nil {
		return &Resolver{}
	}
	return &Resolver{
		Name:    _resolvconf,
		Server:  net.JoinHostPort(c.Servers[0], c.Port),
		Timeout: 8 * time.Second,
	}
}

// ResolverAuto ...
func ResolverAuto() *Resolver {
	switch {
	case isFile(_resolvconf) && ResolverResolvConf().IsReachable():
		return ResolverResolvConf()
	case ResolverLocalhost().IsReachable():
		return ResolverLocalhost()
	default:
		for p := range dnsProvider {
			resolver := resolverProviderName(p, true)
			if resolver.IsReachable() {
				return resolver
			}
		}
		for p := range dnsProvider {
			resolver := resolverProviderName(p, false)
			if resolver.IsReachable() {
				return resolver
			}
		}
	}
	return &Resolver{}
}

// Lookup ...
func (r *Resolver) Lookup(query string, rType uint16) ([]string, error) {
	return r.resolvePlain(query, rType)
}

// LookupAddr ...
func (r *Resolver) LookupAddr(query string, rType uint16) ([]netip.Addr, error) {
	return r.resolveAddr(query, rType)
}

// LookupAddrs ...
func (r *Resolver) LookupAddrs(query string, rTypes []uint16) ([]netip.Addr, error) {
	return r.resolveAddrs(query, rTypes)
}

// ReverseLookupIP4 ...
func (r *Resolver) ReverseLookupIP4(ip4 string) (string, error) {
	return r.reverseIP4(_emptyAddr, ip4)
}

// ReverseLookupIP4Addr ...
func (r *Resolver) ReverseLookupIP4Addr(addrIP4 netip.Addr) (string, error) {
	return r.reverseIP4(addrIP4, _empty)
}

// Exchange ...
func (r *Resolver) Exchange(query string, raw, summary bool, rTypes []uint16) (*Answer, error) {
	return r.exchangeAll(query, raw, summary, rTypes)
}

// IsReachable ...
func (r *Resolver) IsReachable() bool {
	err := r.IsFunctional()
	return err == nil 
}

// IsFunctional ...
func (r *Resolver) IsFunctional() error {
	if _, ok := resolverReachableMap.Load(r.Server); ok {
		return nil
	}
	_, err := r.resolve(_ping, dns.TypeA)
	if err != nil {
		return err
	}
	if r.DoT {
		resolverReachableMap.Store(r.Server, true)
	}
	resolverReachableMap.Store(r.Server, false)
	return nil
}
