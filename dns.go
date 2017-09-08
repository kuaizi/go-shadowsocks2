package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/smallnest/iprange"
)

const (
	defaultUDPSize = 1460

	dnsTimeout time.Duration = 6 * time.Second
)

var (
	// www.hkdnr.hk NS record
	probeNameServers = []string{"ns7.hkirc.net.hk", "ns8.hkirc.net.hk"}

	directLookupId uint32
)

type DnsError struct {
	rcode int
}

func (e *DnsError) Error() string {
	return fmt.Sprintf("dns error with rcode=%s", dns.RcodeToString[e.rcode])
}

type FakeDns struct {
	port int

	chinaDNS []string

	mapping      map[string]string
	mappingMutex *sync.RWMutex

	fakeDnsIp4 uint32

	cacheFile *os.File

	chnRanges []*iprange.IPV4Range
}

func NewFakeDns(port int) *FakeDns {
	var chnDns []string
	const overtureVpnConfPath = "overture-vpn.conf"
	if b, err := ioutil.ReadFile(overtureVpnConfPath); err == nil {
		var overtureConf = struct {
			AlternativeDNS []struct {
				Address string
			}
		}{}
		if err := json.Unmarshal(b, &overtureConf); err == nil {
			for _, d := range overtureConf.AlternativeDNS {
				chnDns = append(chnDns, d.Address)
			}
		} else {
			logf("parse %s: %v", overtureVpnConfPath, err)
		}
	} else {
		logf("read %s: %v", overtureVpnConfPath, err)
	}
	if len(chnDns) == 0 {
		log.Fatalln("can not get custom dns")
	} else {
		logf("chinadns: %v", chnDns)
	}
	return &FakeDns{
		port:         port,
		chinaDNS:     chnDns,
		mapping:      make(map[string]string),
		mappingMutex: &sync.RWMutex{},
		fakeDnsIp4:   184549376, // 11.0.0.0
	}
}

func (f *FakeDns) Start() {
	cacheWg := &sync.WaitGroup{}
	cacheWg.Add(2)
	go func() {
		const cachePath = "fakedns.cache"
		defer cacheWg.Done()
		var err error
		f.cacheFile, err = os.OpenFile(cachePath, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			log.Fatalf("open %s: %v", cachePath, err)
		}
		scanner := bufio.NewScanner(f.cacheFile)
		f.mappingMutex.Lock()
		for scanner.Scan() {
			domain := scanner.Text()
			ip := f.newFakeIp()
			f.mapping[ip] = domain
			f.mapping[domain] = ip
		}
		f.mappingMutex.Unlock()
		if err = scanner.Err(); err != nil {
			log.Fatalf("scan %s: %v", cachePath, err)
		}
		logf("loaded %s %d items", cachePath, len(f.mapping))
	}()
	go func() {
		const chnListPath = "bypass-lan-china.acl"
		defer cacheWg.Done()
		f.chnRanges = iprange.ParseIPV4RangeFromFile(chnListPath)
		lessFunc := func(i, j int) bool {
			return f.chnRanges[i].Start < f.chnRanges[j].Start
		}
		if !sort.SliceIsSorted(f.chnRanges, lessFunc) {
			sort.Slice(f.chnRanges, lessFunc)
		}
		logf("loaded %s %d items", chnListPath, len(f.chnRanges))
	}()
	probeDnsSrv := f.findProbeDnsSrv()
	logf("probe dns server: %s", probeDnsSrv)
	probeDnsSrvs := []string{probeDnsSrv}
	cacheWg.Wait()
	srv := dns.Server{
		Addr: fmt.Sprintf("127.0.0.1:%d", f.port),
		Net:  "udp4",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			ok := false
			var q dns.Question
			for i := range r.Question {
				if r.Question[i].Qtype != dns.TypeAAAA {
					q = r.Question[i]
					ok = true
				}
			}
			logf("dns query: %#v", q)
			if !ok {
				dns.HandleFailed(w, r)
				return
			}
			r.Question = []dns.Question{q}
			respMsg := func() *dns.Msg {
				var ip string
				shouldProbe := probeDnsSrv != "" && q.Qtype == dns.TypeA && strings.Count(q.Name, ".") > 1
				f.mappingMutex.RLock()
				ip, ok := f.mapping[q.Name]
				f.mappingMutex.RUnlock()
				if ok {
					if ip != "" {
						return fakeRespDnsMsg(r, ip)
					} else {
						shouldProbe = false
					}
				}
				probeCh := make(chan string, 1)
				if shouldProbe {
					go func() {
						defer close(probeCh)
						resp, err := directQueryWithMsg(r, probeDnsSrvs)
						if err != nil {
							return
						}
						if resp.Rcode == dns.RcodeSuccess {
							logf("domain %s polluted", q.Name)
							ip := f.newFakeIp()
							f.insertFakeDnsRecord(ip, q.Name)
							probeCh <- ip
						} else {
							f.insertFakeDnsRecord("", q.Name)
						}
					}()
				}
				realCh := make(chan *dns.Msg, 1)
				go func() {
					defer close(realCh)
					resp, err := directQueryWithMsg(r, f.chinaDNS)
					if err == nil {
						realCh <- resp
					} else {
						realCh <- failedDnsMsg(r)
					}
				}()
				var respMsg *dns.Msg
				select {
				case ip = <-probeCh:
					if ip != "" {
						return fakeRespDnsMsg(r, ip)
					} else {
						respMsg = <-realCh
					}
				case respMsg = <-realCh:
					if shouldProbe {
						ip = <-probeCh
						if ip != "" {
							return fakeRespDnsMsg(r, ip)
						}
					}
				}
				if respMsg.Rcode == dns.RcodeSuccess {
					var chnAnswers []dns.RR
					var chnACnt int
					for _, answer := range respMsg.Answer {
						if dnsA, ok := answer.(*dns.A); ok {
							if iprange.IPv4Contains(f.chnRanges, dnsA.A) {
								chnAnswers = append(chnAnswers, answer)
								chnACnt++
							}
						} else {
							chnAnswers = append(chnAnswers, answer)
						}
					}
					if chnACnt == 0 {
						logf("domain %s has no chn ips, fake it", q.Name)
						ip = f.newFakeIp()
						f.insertFakeDnsRecord(ip, q.Name)
						respMsg = fakeRespDnsMsg(r, ip)
					} else {
						respMsg.Answer = chnAnswers
					}
				}
				return respMsg
			}()
			w.WriteMsg(respMsg)
		}),
		UDPSize: defaultUDPSize,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("dns listen: %v", err)
	}
}

func (f *FakeDns) insertFakeDnsRecord(ip string, domain string) {
	f.mappingMutex.Lock()
	if ip != "" {
		f.mapping[ip] = domain
		oldIp, ok := f.mapping[domain]
		if !ok || oldIp == "" {
			fmt.Fprintln(f.cacheFile, domain)
		}
		logf("fakeDns insert: %s -> %s", domain, ip)
	} else {
		logf("bypassDns %s", domain)
	}
	f.mapping[domain] = ip
	f.mappingMutex.Unlock()
}

func (f *FakeDns) newFakeIp() string {
	newIpInt := atomic.AddUint32(&f.fakeDnsIp4, 1)
	newIpBytes := make([]byte, net.IPv4len)
	binary.BigEndian.PutUint32(newIpBytes, newIpInt)
	return net.IP(newIpBytes).String()
}

func (f *FakeDns) Replace(orig socks.Addr) socks.Addr {
	ip, port, _ := net.SplitHostPort(orig.String())
	if net.ParseIP(ip) == nil {
		return orig
	}
	f.mappingMutex.RLock()
	domain := f.mapping[ip]
	f.mappingMutex.RUnlock()
	if domain == "" {
		return orig
	}
	if strings.HasSuffix(domain, ".") {
		domain = domain[:len(domain)-1]
	}
	addr := socks.ParseAddr(net.JoinHostPort(domain, port))
	if addr == nil {
		return orig
	}
	logf("fakeDns replace: %s -> %s", orig, addr)
	return addr
}

func failedDnsMsg(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	return m
}

func fakeRespDnsMsg(r *dns.Msg, ip string) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeSuccess)
	m.CheckingDisabled = true
	q := r.Question[0]
	m.Question = []dns.Question{q}
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: q.Qtype,
			Ttl:    1,
			Class:  dns.ClassINET,
		},
		A: net.ParseIP(ip),
	}}
	return m
}

func directLookup(domain string, dnsSrv []string) ([]string, error) {
	logf("direct lookup %s @%s", domain, dnsSrv)
	m := new(dns.Msg)
	m.Id = uint16(atomic.AddUint32(&directLookupId, 1))
	m.Opcode = dns.OpcodeQuery
	m.CheckingDisabled = true
	m.RecursionDesired = true
	m.Question = []dns.Question{
		{
			Name:   domain + ".",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		},
	}
	resp, err := directQueryWithMsg(m, dnsSrv)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, &DnsError{resp.Rcode}
	}
	var ips []string
	for _, answer := range resp.Answer {
		if dnsA, ok := answer.(*dns.A); ok {
			ips = append(ips, dnsA.A.String())
		}
	}
	return ips, nil
}

func directQueryWithMsg(req *dns.Msg, dnsSrvs []string) (resp *dns.Msg, err error) {
	for _, dnsSrv := range dnsSrvs {
		resp, err = func() (*dns.Msg, error) {
			co := new(dns.Conn)
			co.UDPSize = defaultUDPSize
			if co.Conn, err = net.DialTimeout("udp4", dnsSrv, dnsTimeout); err != nil {
				return nil, err
			}
			defer co.Close()
			co.SetWriteDeadline(time.Now().Add(dnsTimeout))
			if err = co.WriteMsg(req); err != nil {
				return nil, err
			}
			co.SetReadDeadline(time.Now().Add(dnsTimeout))
			return co.ReadMsg()

		}()
		if err == nil {
			if resp.Rcode != dns.RcodeServerFailure {
				break
			}
		}
	}
	return resp, err
}

func (f *FakeDns) findProbeDnsSrv() string {
	probeDnsSrvCh := make(chan string, 1)
	var chClosed atomic.Value
	chClosed.Store(false)
	wg := &sync.WaitGroup{}
	for _, s := range probeNameServers {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			ips, err := directLookup(s, f.chinaDNS)
			if err != nil {
				logf("lookup %s: %v", s, err)
				return
			}
			for _, ip := range ips {
				wg.Add(1)
				go func(ip string) {
					defer wg.Done()
					if chClosed.Load().(bool) {
						return
					}
					ip += ":53"
					_, err := directLookup("www.baidu.com", []string{ip})
					logf("probe server %s return: %v", ip, err)
					if err != nil {
						if _, ok := err.(*DnsError); ok {
							if !chClosed.Load().(bool) {
								select {
								case probeDnsSrvCh <- ip:
									chClosed.Store(true)
								default:
								}
							}
						}
					}
				}(ip)
			}
		}(s)
	}
	wgCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(wgCh)
	}()
	select {
	case ip := <-probeDnsSrvCh:
		go func() {
			for range probeDnsSrvCh {
			}
		}()
		return ip
	case <-wgCh:
		select {
		case ip := <-probeDnsSrvCh:
			return ip
		default:
			return ""
		}
	}
}
