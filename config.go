package main

import (
	"errors"
	"flag"
	"log"
	"net/url"
	"os"
	"strconv"
)

type ProxyConfig struct {
	Key          string
	Cert         string
	KeyFile      string
	CertFile     string
	ClientCA     string
	ClientCAFile string
	Target       string
	Port         int
}

func LoadConfig() *ProxyConfig {
	key := flag.String("key", "", "")
	cert := flag.String("cert", "", "")

	keyFile := flag.String("key-file", "", "")
	certFile := flag.String("cert-file", "", "")

	clientCA := flag.String("client-ca", "", "")
	clientCAFile := flag.String("client-ca-file", "", "")

	target := flag.String("target", "http://localhost:8089", "")
	port := flag.Int("port", -1, "")

	flag.Parse()

	config := &ProxyConfig{}
	config.Key = flagOrEnv(key, "KEY")
	config.Cert = flagOrEnv(cert, "CERT")
	config.KeyFile = flagOrEnv(keyFile, "KEYFILE")
	config.CertFile = flagOrEnv(certFile, "CERTFILE")
	config.ClientCA = flagOrEnv(clientCA, "CLIENT_CA")
	config.ClientCAFile = flagOrEnv(clientCAFile, "CLIENT_CA_FILE")
	config.Target = flagOrEnv(target, "TARGET")

	if (*port) == 0 {
		portFromEnv := os.Getenv("PORT")
		parsedPort, err := strconv.Atoi(portFromEnv)
		if err != nil {
			log.Printf("Setting default port")
			config.Port = 8443
		} else {
			config.Port = parsedPort
		}
	} else {
		config.Port = *port
	}

	return config
}

func (config *ProxyConfig) Validate() error {
	if len(config.Key) < 100 && len(config.KeyFile) == 0 {
		return errors.New("No Key or keyfile specified");
	}

	if len(config.Cert) < 100 && len(config.CertFile) == 0 {
		return errors.New("No certificate or certificate file specified")
	}

	if config.Port <= 0 || config.Port > 65535 {
		return errors.New("Invalid Port speficied")
	}

	if _, err := url.Parse(config.Target); err != nil {
		return err
	}

	return nil
}

func flagOrEnv(parsedFlag *string, env string) string {
	tmp := *parsedFlag
	if len(tmp) > 0 {
		return tmp
	}

	return os.Getenv(env)
}