package main

import (
	"flag"
	"log"
	"github.com/spf13/viper"
	"github.com/abourget/goproxy"
	"fmt"
	"io/ioutil"
)

// This is a test...

// Global variables. These will be read in by default from config.toml but can be overridden on the command line
var timeoutStr string
var matchTimeoutStr string
var httpAddr string
var httpsAddr string
var httpDebug string
var logRequests uint64
var cacheDir string
var maxAgeArg string
var caCert string
var caKey string

func makeCertificate(certPath, keyPath string) (*goproxy.GoproxyConfig, error) {
	cert, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("cannot load CA certificate: %s", err)
	}
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("cannot load CA key: %s", err)
	}
	
	ca, err := goproxy.LoadCAConfig(cert, key)
	//ca, err := tls.X509KeyPair(cert, key)
	return ca, err
}


func main() {
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	addr := flag.String("addr", ":8080", "proxy listen address")
	flag.Parse()
	
		// Read configuration values
	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/winston/")

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalln(err)
		log.Fatalln("Config file not found.")
	} else {
		flag.StringVar(&timeoutStr, "timeout", viper.GetString("timeout"), "HTTP/TCP connections global timeout")
		flag.StringVar(&matchTimeoutStr, "match_timeout", viper.GetString("match_timeout"), "request matching timeout")		        
		flag.StringVar(&httpAddr, "http", viper.GetString("http"), "HTTP handler address")
		flag.StringVar(&httpsAddr, "https", viper.GetString("https"), "HTTPS handler address") 
		flag.StringVar(&httpDebug, "debug_addr", viper.GetString("debug-addr"), "HTTP debug address")
		logRequests = 0
		if viper.GetInt("log") == 1 {
			logRequests = 1
		}
			
		flag.StringVar(&cacheDir, "cache", viper.GetString("cache"), "cache directory") 
		flag.StringVar(&maxAgeArg, "max_age", viper.GetString("max_age"), "cached entries max age")
		flag.StringVar(&caCert, "ca_cert", viper.GetString("ca_cert"), "path to CA certificate")
		flag.StringVar(&caKey, "ca_key", viper.GetString("ca_key"), "path to CA key")
	}
	
	// Initialize the proxy
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose
	
	// Create a root certificate
	if caCert == "" || caKey == "" {
		return fmt.Errorf("CA certificate and key must be specified")
	}
	ca, err := makeCertificate(caCert, caKey)
	if err != nil {
		return err
	}
	
	// Apply the root certificate to the proxy	
	proxy.SetMITMCertConfig(ca)
	
	
	// Simple test to redirect https://google.com to Bing
	// Make sure other SSL sites work normally
	proxy.HandleConnectFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			ctx.Logf("*** In Connect Handler. Host: %s SNIHost: %s", ctx.Host(), ctx.SNIHost())
			if ctx.SNIHost() == "google.com:443" {
					ctx.Logf("Intercepted Google.com... redirecting to Bing!")

					ctx.SetDestinationHost("www.bing.com:443")
					// so that Bing receives the right `Host:` header
					ctx.Req.Host = "www.bing.com"
					return goproxy.MITM
			}

			return goproxy.FORWARD
	})

		
		
	log.Fatal(proxy.ListenAndServe(*addr))
}