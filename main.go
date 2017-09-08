package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/juju/gnuflag"
	"github.com/shadowsocks/go-shadowsocks2/core"
)

var config struct {
	Verbose    bool
	UDPTimeout time.Duration
}

var (
	isVpn   bool
	fakeDns *FakeDns
)

func logf(f string, v ...interface{}) {
	if config.Verbose {
		log.Printf(f, v...)
	}
}

func main() {
	runtime.GOMAXPROCS(1)

	var flags struct {
		Client    string
		Server    string
		Cipher    string
		Key       string
		Password  string
		Keygen    int
		Socks     string
		RedirTCP  string
		RedirTCP6 string
		TCPTun    string
		UDPTun    string
	}

	flag := gnuflag.NewFlagSet(os.Args[0], gnuflag.ContinueOnError)

	var bindAddr string
	var bindPort int
	var confPath string
	flag.BoolVar(&isVpn, "V", false, "vpn mode")
	flag.StringVar(&bindAddr, "b", "", "client bind address")
	flag.IntVar(&bindPort, "l", 0, "client bind port")
	flag.StringVar(&confPath, "c", "", "conf path")
	flag.Bool("u", true, "udp")
	flag.Bool("fast-open", false, "fast-open")
	flag.Int("t", 0, "timeout")
	flag.String("acl", "", "acl")

	flag.BoolVar(&config.Verbose, "verbose", false, "verbose mode")
	flag.StringVar(&flags.Cipher, "cipher", "AEAD_CHACHA20_POLY1305", "available ciphers: "+strings.Join(core.ListCipher(), " "))
	flag.StringVar(&flags.Key, "key", "", "base64url-encoded key (derive from password if empty)")
	flag.IntVar(&flags.Keygen, "keygen", 0, "generate a base64url-encoded random key of given length in byte")
	flag.StringVar(&flags.Password, "password", "", "password")
	flag.StringVar(&flags.Server, "s", "", "server listen address or url")
	flag.StringVar(&flags.Socks, "socks", "", "(client-only) SOCKS listen address")
	flag.StringVar(&flags.RedirTCP, "redir", "", "(client-only) redirect TCP from this address")
	flag.StringVar(&flags.RedirTCP6, "redir6", "", "(client-only) redirect TCP IPv6 from this address")
	flag.StringVar(&flags.TCPTun, "tcptun", "", "(client-only) TCP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
	flag.StringVar(&flags.UDPTun, "udptun", "", "(client-only) UDP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
	flag.DurationVar(&config.UDPTimeout, "udptimeout", 5*time.Minute, "UDP tunnel timeout")
	flag.Parse(false, os.Args[1:])

	if isVpn {
		os.Chdir("/data/data/com.github.shadowsocks/files")
		f, _ := os.OpenFile("sslocal.stdout", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		log.SetOutput(f)
		log.Println("now in vpn mode")
	}

	if flags.Keygen > 0 {
		key := make([]byte, flags.Keygen)
		io.ReadFull(rand.Reader, key)
		fmt.Println(base64.URLEncoding.EncodeToString(key))
		return
	}

	var key []byte
	if flags.Key != "" {
		k, err := base64.URLEncoding.DecodeString(flags.Key)
		if err != nil {
			log.Fatal(err)
		}
		key = k
	}

	if bindAddr != "" && bindPort > 0 {
		flags.Socks = fmt.Sprintf("%s:%d", bindAddr, bindPort)
	}
	if confPath != "" {
		type jsonConf struct {
			Server   string `json:"server"`
			Port     int    `json:"server_port"`
			Password string `json:"password"`
			Method   string `json:"method"`
		}
		b, err := ioutil.ReadFile(confPath)
		if err != nil {
			log.Fatalf("read %s: %v", confPath, err)
		}
		var c jsonConf
		if err := json.Unmarshal(b, &c); err != nil {
			log.Fatalf("parse json conf: %v", err)
		}
		ssUrl := url.URL{
			Scheme: "ss",
			User:   url.UserPassword(c.Method, c.Password),
			Host:   fmt.Sprintf("%s:%d", c.Server, c.Port),
		}
		flags.Client = ssUrl.String()
		if isVpn {
			fakeDns = NewFakeDns(bindPort + 53)
			go fakeDns.Start()
		}
	}

	if flags.Client != "" { // client mode
		addr := flags.Client
		cipher := flags.Cipher
		password := flags.Password
		var err error

		if strings.HasPrefix(addr, "ss://") {
			addr, cipher, password, err = parseURL(addr)
			if err != nil {
				log.Fatal(err)
			}
		}

		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			log.Fatal(err)
		}

		if flags.UDPTun != "" {
			for _, tun := range strings.Split(flags.UDPTun, ",") {
				p := strings.Split(tun, "=")
				go udpLocal(p[0], addr, p[1], ciph.PacketConn)
			}
		}

		if flags.TCPTun != "" {
			for _, tun := range strings.Split(flags.TCPTun, ",") {
				p := strings.Split(tun, "=")
				go tcpTun(p[0], addr, p[1], ciph.StreamConn)
			}
		}

		if flags.Socks != "" {
			go socksLocal(flags.Socks, addr, ciph.StreamConn)
		}

		if flags.RedirTCP != "" {
			go redirLocal(flags.RedirTCP, addr, ciph.StreamConn)
		}

		if flags.RedirTCP6 != "" {
			go redir6Local(flags.RedirTCP6, addr, ciph.StreamConn)
		}
	}

	if flags.Client == "" && flags.Server == "" {
		flag.Usage()
		return
	}

	if flags.Server != "" { // server mode
		addr := flags.Server
		cipher := flags.Cipher
		password := flags.Password
		var err error

		if strings.HasPrefix(addr, "ss://") {
			addr, cipher, password, err = parseURL(addr)
			if err != nil {
				log.Fatal(err)
			}
		}

		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			log.Fatal(err)
		}

		go udpRemote(addr, ciph.PacketConn)
		go tcpRemote(addr, ciph.StreamConn)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func parseURL(s string) (addr, cipher, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	addr = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}
