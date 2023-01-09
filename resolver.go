package dnsresolver

import (
	"errors"
	"net/netip"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// const
const (
	_dnsPort = ":53"
	_dotPort = ":853"
)

// var
var (
	_emptyAddr           = netip.Addr{}
	_emptyAddrs          = []netip.Addr{}
	_emptyStrings        = []string{}
	resolverReachableMap sync.Map
)

// response ...
type response struct {
	rtype   uint16
	raw     string
	summary string
}

// rTypeAll returns a list of all DNS Record Types
func rTypeAll() []uint16 {
	all := make([]uint16, len(dns.TypeToString))
	for rType := range dns.TypeToString {
		all = append(all, rType)
	}
	return all
}

// exchangeAll
func (r *Resolver) exchangeAll(query string, raw, summary bool, rTypes []uint16) (*Answer, error) {
	var (
		bg              sync.WaitGroup
		responseChannel = make(chan response, 25)
	)
	go func() {
		var err error
		var conn *dns.Conn
		proto := r.proto()
		if r.DoT {
			if r.TLSKeyPin != _empty && r.TLSConfig.VerifyConnection == nil { // sanitycheck, gate - do not recover
				panic("[dnsinfo] [internal] [security] [keypin:active] no tlsconfig.VerifyConnection func set")
			}
			conn, err = dns.DialTimeoutWithTLS(proto, r.Server, r.TLSConfig, r.Timeout)
		} else {
			conn, err = dns.DialTimeout(proto, r.Server, r.Timeout)
		}
		if err != nil {
			responseChannel <- response{dns.TypeNone, _empty, _rfail + err.Error() + _linefeed}
			close(responseChannel)
			return
		}
		for _, rType := range rTypes {
			rType := rType
			switch rType {
			case dns.TypeANY:
				continue // skip ANY
			case dns.TypeNone, dns.TypeReserved, dns.TypeNULL, dns.TypeUNSPEC:
				continue // skip bogous types
			case dns.TypeMAILA, dns.TypeMAILB, dns.TypeOPT, dns.TypeTKEY, dns.TypeTSIG, dns.TypeAXFR, dns.TypeIXFR:
				continue // skip non-request types
			}
			bg.Add(1)
			r.querySend(conn, proto, query, rType, raw, summary, &responseChannel, &bg)
		}
		bg.Wait()
		close(responseChannel)
	}()
	rawMap := make(map[uint16]string, len(rTypes))
	summaryMap := make(map[uint16]string, len(rTypes))
	for r := range responseChannel {
		switch r.rtype {
		case dns.TypeNone:
		case dns.TypeReserved:
		}
		rawMap[r.rtype] = r.raw
		summaryMap[r.rtype] = r.summary
	}
	return &Answer{rawMap, summaryMap}, nil
}

// querySend ...
func (r *Resolver) querySend(conn *dns.Conn, proto, query string, rType uint16, raw, summary bool, responseChannel *chan response, bg *sync.WaitGroup) {
	defer bg.Done()
	// _,_ = conn, proto
	rsp, err := r.resolveViaConn(conn, proto, query, rType)
	if err != nil {
		*responseChannel <- response{rType, removeEmptyLines(rsp.String()), _rfail + err.Error() + _linefeed}
		return
	}
	sendResponse := false
	var rawdat strings.Builder
	if len(rsp.Answer) > 0 {
		if raw {
			sendResponse = true
			rawdat.WriteString(removeEmptyLines(rsp.String()))
		}
		var sum strings.Builder
		for _, a := range rsp.Answer {
			line := a.String()
			s := strings.Fields(line)
			if len(s) > 3 && s[3] == dns.TypeToString[rType] {
				if summary {
					sendResponse = true
					sum.WriteString(_dns)
					sum.WriteString(dns.TypeToString[rType])
					sum.WriteString(_sep)
					sum.WriteString(line)
					sum.WriteString(_linefeed)
				}
			}
		}
		if sendResponse {
			*responseChannel <- response{rType, rawdat.String(), sum.String()}
		}
	}
}

// resolve ...
func (r *Resolver) resolve(query string, rType uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(query), rType)
	var err error
	var conn *dns.Conn
	proto := r.proto()
	if r.DoT {
		if r.TLSKeyPin != _empty && r.TLSConfig.VerifyConnection == nil { // sanitycheck
			panic("[dnsinfo] [internal] [security] [keypin:active] no tlsconfig.VerifyConnection func set")
		}
		conn, err = dns.DialTimeoutWithTLS(proto, r.Server, r.TLSConfig, r.Timeout)
	} else {
		conn, err = dns.DialTimeout(proto, r.Server, r.Timeout)
	}
	if err != nil {
		return &dns.Msg{}, errors.New(_errLookup + r.Server + _sep + proto + _sep + err.Error())
	}
	dnsClient := new(dns.Client)
	rsp, _, err := dnsClient.ExchangeWithConn(msg, conn)
	if err != nil {
		if proto == _udp && !r.NoTCP { // udp faild, retry tcp
			proto = _tcp
			conn, err = dns.DialTimeout(proto, r.Server, r.Timeout)
			if err != nil {
				q := dns.TypeToString[rType]
				return &dns.Msg{}, errors.New(q + _errLookup + r.Server + _sep + proto + _sep + err.Error())
			}
			rsp, _, err = dnsClient.ExchangeWithConn(msg, conn)
			if err != nil {
				q := dns.TypeToString[rType]
				return &dns.Msg{}, errors.New(q + _errLookup + r.Server + _sep + proto + _sep + err.Error())
			}
			if rsp.Rcode != dns.RcodeSuccess {
				q := dns.TypeToString[rType]
				return rsp, errors.New(q + _errLookup + r.Server + _sep + proto + _sep + dns.RcodeToString[rsp.Rcode])
			}
			return rsp, nil
		}
		q := dns.TypeToString[rType]
		return &dns.Msg{}, errors.New(q + _errLookup + r.Server + _sep + proto + _sep + err.Error())
	}
	if rsp.Rcode != dns.RcodeSuccess {
		return rsp, errors.New(_errLookup + r.Server + _sep + proto + _sep + dns.RcodeToString[rsp.Rcode])
	}
	return rsp, nil
}

// resolve ...
func (r *Resolver) resolveViaConn(conn *dns.Conn, proto, query string, rType uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(query), rType)
	dnsClient := new(dns.Client)
	rsp, _, err := dnsClient.ExchangeWithConn(msg, conn)
	if err != nil {
		if proto == _udp && !r.NoTCP { // udp faild, retry tcp
			proto = _tcp
			conn, err = dns.DialTimeout(proto, r.Server, r.Timeout)
			if err != nil {
				q := dns.TypeToString[rType]
				return &dns.Msg{}, errors.New(q + _errLookup + r.Server + _sep + proto + _sep + err.Error())
			}
			rsp, _, err = dnsClient.ExchangeWithConn(msg, conn)
			if err != nil {
				q := dns.TypeToString[rType]
				return &dns.Msg{}, errors.New(q + _errLookup + r.Server + _sep + proto + _sep + err.Error())
			}
			if rsp.Rcode != dns.RcodeSuccess {
				q := dns.TypeToString[rType]
				return rsp, errors.New(q + _errLookup + r.Server + _sep + proto + _sep + dns.RcodeToString[rsp.Rcode])
			}
			return rsp, nil
		}
		q := dns.TypeToString[rType]
		return &dns.Msg{}, errors.New(q + _errLookup + r.Server + _sep + proto + _sep + err.Error())
	}
	if rsp.Rcode != dns.RcodeSuccess {
		return rsp, errors.New(_errLookup + r.Server + _sep + proto + _sep + dns.RcodeToString[rsp.Rcode])
	}
	return rsp, nil
}

// resolvePlain ...
func (r *Resolver) resolvePlain(query string, rType uint16) ([]string, error) {
	var all []string
	rsp, err := r.resolve(query, rType)
	if err != nil {
		return _emptyStrings, errors.New(_errLookup + err.Error())
	}
	for _, a := range rsp.Answer {
		line := a.String()
		s := strings.Fields(line)
		if len(s) > 3 && s[3] == dns.TypeToString[rType] {
			all = append(all, line)
		}
	}
	if len(all) == 0 {
		return _emptyStrings, errors.New(_errLookup + _noAnswer)
	}
	return all, nil
}

// resolveAddr ...
func (r *Resolver) resolveAddr(query string, rType uint16) ([]netip.Addr, error) {
	switch rType {
	case dns.TypeA:
	case dns.TypeAAAA:
	default:
		return _emptyAddrs, errors.New(_errLookup + _errUnsupportedType + dns.TypeToString[rType])
	}
	rsp, err := r.resolve(query, rType)
	if err != nil {
		return _emptyAddrs, errors.New(_errLookup + err.Error())
	}
	var all []netip.Addr
	for _, a := range rsp.Answer {
		line := a.String()
		s := strings.Fields(line)
		if len(s) > 3 && s[3] == dns.TypeToString[rType] {
			if ip, err := netip.ParseAddr(s[4]); err == nil {
				all = append(all, ip)
			}
		}
	}
	if len(all) == 0 {
		return _emptyAddrs, errors.New(_errLookup + _noAnswer)
	}
	return all, nil
}

// resolveAddrs ...
func (r *Resolver) resolveAddrs(query string, rTypes []uint16) ([]netip.Addr, error) {
	var err error
	var failCounter int
	var all, subset []netip.Addr
	for _, rType := range rTypes {
		if subset, err = r.resolveAddr(query, rType); err != nil {
			failCounter++
			continue
		}
		all = append(all, subset...)
	}
	if failCounter == len(rTypes) {
		return _emptyAddrs, err
	}
	return all, nil
}

// reverseIP4 ...
func (r *Resolver) reverseIP4(addrIP4 netip.Addr, ip4 string) (string, error) {
	var err error
	if ip4 == _empty {
		ip4 = addrIP4.String()
	}
	if addrIP4 == _emptyAddr {
		if addrIP4, err = netip.ParseAddr(ip4); err != nil {
			return _empty, errors.New(_errReverseLookup + ip4 + _sep + err.Error())
		}
	}
	if !addrIP4.IsValid() || addrIP4.IsUnspecified() || !addrIP4.Is4() {
		return _empty, errors.New(_errReverseLookup + ip4)
	}
	s := strings.Split(ip4, _dot)
	if len(s) != 4 {
		return _empty, errors.New(_errReverseLookup + ip4)
	}
	resp, err := r.resolvePlain(s[3]+_dot+s[2]+_dot+s[1]+_dot+s[0]+_reverseIP4Suffix, dns.TypePTR)
	if err != nil {
		return _empty, errors.New(_errReverseLookup + ip4 + _sep + err.Error())
	}
	return resp[0], nil
}
