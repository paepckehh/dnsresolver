// package dnsresolver ...
package dnsresolver

// import section

// type section
type (
	// provider ...
	provider struct {
		ip  string // target ip address
		pin string // DoT/TLS x509 certificate keypin base64 encoded
	}
)

// var section
var (
	// dnsProvider ...
	dnsProvider = map[string]*provider{
		"google":      {"8.8.8.8", "TXV9bLOi7Bt/vB9N8l1yGWokU85gKfaiLtYaV+zWkQM="},
		"google2":     {"8.8.4.4", "TXV9bLOi7Bt/vB9N8l1yGWokU85gKfaiLtYaV+zWkQM="},
		"cloudflare":  {"1.1.1.1", "MnLdGiqUGYhtyinlrGTC4FZdDyDXv4NOWFGnXW3ur14="},
		"cloudflare2": {"1.0.0.1", "MnLdGiqUGYhtyinlrGTC4FZdDyDXv4NOWFGnXW3ur14="},
		"quad9":       {"9.9.9.9", "/SlsviBkb05Y/8XiKF9+CZsgCtrqPQk5bh47o0R3/Cg="},
		"quad92":      {"9.9.9.10", "/SlsviBkb05Y/8XiKF9+CZsgCtrqPQk5bh47o0R3/Cg="},
	}
)

// resolverProviderName ...
func resolverProviderName(name string, dot bool) *Resolver {
	resolver := &Resolver{}
	provider, ok := dnsProvider[name]
	if !ok {
		return &Resolver{Name: "Unknown Resolver Name"}
	}
	resolver.Name = name
	resolver.Server = provider.ip + _dnsPort
	if dot {
		if provider.pin == "" {
			return &Resolver{Name: "DoT requested, but keypin missing"}
		}
		resolver.DoT = true
		resolver.Server = provider.ip + _dotPort
		resolver.TLSKeyPin = provider.pin
		resolver.TLSConfig = tlsConfigPin(resolver)
	}
	return resolver
}

// proto ...
func (r *Resolver) proto() string {
	prefix, suffix := _udp, _empty
	switch {
	case r.NoUDP && r.NoTCP && !r.DoT:
		panic("[dnsinfo] [resolver] [internal] [error] [unable to continue] udp, tcp and DoT(tcp-tls) disabled" + r.Server)
	case r.DoT:
		r.NoTCP = true
		r.NoUDP = true
		prefix = _tcptls
	case r.NoUDP:
		prefix = _tcp
	}
	switch {
	case r.NoIP4 && r.NoIP6:
		panic("[dnsinfo] [resolver] [internal] [error] [unable to continue] protocol ip4 and ip6 disabled: " + r.Server)
	case r.NoIP4:
		suffix = _six
	case r.NoIP6:
		suffix = _four
	}
	return prefix + suffix
}
