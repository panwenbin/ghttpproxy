package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/panwenbin/ghttpclient"
	"github.com/panwenbin/greverseproxy/handlers"
	"github.com/panwenbin/greverseproxy/rules"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

var CaServer string

const (
	DEFAULT_CA_SERVER = "http://gca"
)

func init() {
	CaServer = os.Getenv("CA_SERVER")
	if CaServer == "" {
		CaServer = DEFAULT_CA_SERVER
	}

	initRuleFilename := "init_rules.json"
	_, err := os.Stat(initRuleFilename)
	if err == nil {
		rulesBytes, err := ioutil.ReadFile(initRuleFilename)
		if err != nil {
			log.Println(err)
			return
		}
		initRules := make([]*rules.OutRule, 0)
		err = json.Unmarshal(rulesBytes, &initRules)
		if err != nil {
			log.Println(err)
			return
		}

		for i := range initRules {
			err = rules.Apply(initRules[i])
			if err != nil {
				log.Println(err)
				continue
			}
		}
	}
}

func main() {
	http.HandleFunc("/", handlers.All)
	go http.ListenAndServe(":80", nil)
	listenTls()
}

type ResKeyPair struct {
	CertPEMBlock string `json:"cert"`
	KeyPEMBlock  string `json:"key"`
}

var CertCaches map[string]*tls.Certificate
var CertCachesMutex = sync.RWMutex{}

func init() {
	CertCaches = make(map[string]*tls.Certificate, 0)
}

func listenTls() {
	addr := ":443"
	server := &http.Server{Addr: addr}
	server.TLSConfig = &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			CertCachesMutex.Lock()
			defer CertCachesMutex.Unlock()
			var domain string
			if info.ServerName == "" {
				domain = "127.0.0.1"
			} else {
				splits := strings.Split(info.ServerName, ".")
				if len(splits) > 2 {
					domain = strings.Join(splits[1:], ".")
				} else {
					domain = info.ServerName
				}
			}

			if cacheCert, ok := CertCaches[domain]; ok {
				return cacheCert, nil
			}

			url := fmt.Sprintf("%s/sign/%s", CaServer, domain)
			res := &ResKeyPair{}
			err := ghttpclient.Get(url, nil).ReadJsonClose(res)
			if err != nil {
				return nil, err
			}

			cert, err := tls.X509KeyPair([]byte(res.CertPEMBlock), []byte(res.KeyPEMBlock))
			CertCaches[domain] = &cert
			return &cert, err
		},
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalln(err)
	}

	defer ln.Close()

	err = serveTls(server, ln)
	if err != nil {
		log.Fatalln(err)
	}
}

func serveTls(srv *http.Server, ln net.Listener) error {
	config := cloneTLSConfig(srv.TLSConfig)
	if !strSliceContains(config.NextProtos, "http/1.1") {
		config.NextProtos = append(config.NextProtos, "http/1.1")
	}

	tlsListener := tls.NewListener(ln, config)
	return srv.Serve(tlsListener)
}

func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

func strSliceContains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
