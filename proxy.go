package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
)

const (
	HEADER_FORWARDED_FOR = "X-Forwarded-For"
	HEADER_FORWARDED_HOST = "X-Forwarded-Host"
	HEADER_FORWARDED_PROTO = "X-Forwarded-Proto"
)

type Proxy struct {
	Config *ProxyConfig

	Server *http.Server
	Target *url.URL
}

func NewProxy(config *ProxyConfig) (*Proxy, error) {
	proxy := &Proxy{
		Config: config,
	}

	target, err := url.Parse(proxy.Config.Target)
	if err != nil {
		return nil, err
	}

	proxy.Target = target


	return proxy, nil
}

func (proxy *Proxy) Run() error {
	tlsConfig, err := proxy.makeTlsConfig()
	if err != nil {
		return err
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(proxy.Target)
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		forwardedFor := request.Header.Get(HEADER_FORWARDED_FOR)
		if len(forwardedFor) == 0 {
			request.Header.Set(HEADER_FORWARDED_FOR, request.RemoteAddr)
		}

		forwardedProto := request.Header.Get(HEADER_FORWARDED_PROTO)
		if len(forwardedProto) == 0 {
			request.Header.Set(HEADER_FORWARDED_PROTO, "https")
		}

		forwardedHost := request.Header.Get(HEADER_FORWARDED_HOST)
		if len(forwardedHost) == 0 {
			request.Header.Set(HEADER_FORWARDED_HOST, request.Host)
		}

		reverseProxy.ServeHTTP(response, request)
	})

	listenAddr := fmt.Sprintf("0.0.0.0:%v", proxy.Config.Port)

	proxy.Server = &http.Server{
		Addr: listenAddr,
		Handler: handler,
		TLSConfig: tlsConfig,
	}


	return proxy.Server.ListenAndServeTLS("", "")
}

func (proxy *Proxy) makeTlsConfig() (*tls.Config, error) {
	certificates := make([]tls.Certificate, 0)

	if len(proxy.Config.Cert) > 100 && len(proxy.Config.Key) > 100 {
		cert, err := tls.X509KeyPair([]byte(proxy.Config.Cert), []byte(proxy.Config.Key))
		if err != nil {
			return nil, err
		}

		certificates = append(certificates, cert)
	} else {
		cert, err := tls.LoadX509KeyPair(proxy.Config.CertFile, proxy.Config.KeyFile)
		if err == nil {
			return nil, err
		}

		certificates = append(certificates, cert)
	}

	config := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
		Certificates: certificates,
	}

	if len(proxy.Config.ClientCA) > 100 || len(proxy.Config.ClientCAFile) > 0 {
		certPool := x509.NewCertPool()

		if len(proxy.Config.ClientCA) > 100 {
			certPool.AppendCertsFromPEM([]byte(proxy.Config.ClientCA))
		} else {
			clientCert, err := ioutil.ReadFile(proxy.Config.ClientCAFile)
			if err != nil {
				return nil, err
			}
			certPool.AppendCertsFromPEM(clientCert)
		}

		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = certPool
	}

	return config, nil
}