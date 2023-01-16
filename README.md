# OVERVIEW
[![Go Reference](https://pkg.go.dev/badge/paepcke.de/dnsresolver.svg)](https://pkg.go.dev/paepcke.de/dnsresolver) [![Go Report Card](https://goreportcard.com/badge/paepcke.de/dnsresolver)](https://goreportcard.com/report/paepcke.de/dnsresolver)

[paepche.de/dnsresolver](https://paepcke.de/dnsresolver/)

- Alternative DNS Resolver package with focus on security and speed
- Provides many apis 100% plugin compatible with the golang stdlib net dns resolver, just import & change the prefix, done
- Uses the popular miekg/dns package to enable more flexible options for DNS requests
- TLS/DOT secured transport via fixed and built-in keypin 
- 100% pure go, minimal extenral imports, use as app or api (see api.go)

# TODO

[] DNSSEC validation 
[] DoT/DoH Cert SCT (certificat-transparency) tracking, in addition / partial replacement for fixed keypins
[] advanced caching (see [paepcke.de/dnscache](https://paepcke.de/dnscache/))

# EXTERNAL RESOURCES 

Special thanks goes to:

* Miek for the [dns](https://github.com/miekg/dns) package

# DOCS

[pkg.go.dev/paepcke.de/dnsresolver](https://pkg.go.dev/paepcke.de/dnsresolver)

# CONTRIBUTION

Yes, Please! PRs Welcome! 
