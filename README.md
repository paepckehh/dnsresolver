# Overview 

- Alternative DNS Resolver package with focus on security and speed
- Provides many apis 100% plugin compatible with the golang stdlib net dns resolver, just import & change the prefix, done
- Uses the popular miekg/dns package to enable more flexible options for DNS requests
- TLS/DOT secured transport via fixed and built-in keypin 
- 100% pure go, minimal extenral imports, use as app or api (see api.go)

# Work in progress
- DNSSEC validation 
- DoT/DoH Cert SCT (certificat-transparency) tracking, in addition or as replacement to keypin 
- advanced caching (see paepcke.de/dnscache)
