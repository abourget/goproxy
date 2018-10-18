package goproxy

import (
	"testing"
	"fmt"
	"os"
	"time"
	"sync"
	"math/rand"
)


/* This is a sample benchmark to measure the effect of locking on the certificate store.

   Usage:
  	go test -run=nothing -bench=CertificateSigner
  	go test -run=nothing -bench=DomainRedirect

   To output performance data
  	go test -run=nothing -bench=CertificateSigner -cpuprofile /var/www/html/shared/profile.out

   To view performance data remotely (requires Go 1.10):
	go tool pprof -http=: http://winston.conf/shared/profile.out

   On Windows, you can also test for races. This is a good idea. If PASS, then no race conditions have been detected.
   	go test -run=nothing -bench=. -race

 */

// 10/16/2018 - Original code with mutex around metadata store in signer.go
// 	DNS Precached: 4.6, 4.8, 3.8, 4.7, 6.1 => average: 4.8 sec
//	DNS Fresh: 7.6, 8.1, 6.5, 8.1 => average : 7.6 sec
//		-> One run failed: 14 sec
//      Optimized Chain Lookup: 3.9, 3.9, 3.2, 3.3, 3.5 => average 3.5 sec
func BenchmarkCertificateSigner(b *testing.B) {
	if CA_CERT == nil {
		fmt.Printf("[ERROR] CA_CERT was nil.")
		os.Exit(1)
	}
	if CA_KEY == nil {
		fmt.Printf("[ERROR] CA_KEY was nil.")
		os.Exit(1)
	}
	err := LoadDefaultConfig()

	if err != nil {
		fmt.Printf("[ERROR] Couldn't load Default Config. err=%v\n", err)
		os.Exit(1)
	}
	if GoproxyCaConfig == nil {
		fmt.Printf("[ERROR] GoproxyCaConfig was nil.\n")
		os.Exit(1)
	}

	var domains []string = []string{"twitter.com", "nbc.com", "mercedes-benz.com", "google.com", "facebook.com", "nytimes.com", "washingtonpost.com", "www.latimes.com", "politico.com",
	"drudgereport.com", "microsoft.com", "windows.com", "mcdonalds.com", "winstonprivacy.com", "shopify.com",
	"theguardian.com", "digg.com", "reddit.com", "myspace.com", "wsj.com", "twobithistory.org", "mozilla.org", "youtube.com", "cloudflare.net",
	"sprint.com", "verizon.com"}
	var wg sync.WaitGroup
	b.ResetTimer()
	starttime := time.Now()
		// We should have a winston signed certificate with Twitter fields copied in.
		for i := 0; i < 25; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for n := 0; n < 100; n++ {
					j := rand.Intn(len(domains))

					GoproxyCaConfig.Cert(domains[j])

					certmu.RLock()
					tlsc, ok := GoproxyCaConfig.NameToCertificate[domains[j]]
					certmu.RUnlock()
					if !ok || tlsc == nil {
						fmt.Printf("[ERROR] Certificate fetch failed: %s\n", domains[j])
						//os.Exit(1)
					} /*else {
						fmt.Printf("[SUCCESS] Certificate fetch succeeded. : %s\n", domains[j])
					}*/
				}
			}()
		}

	// Wait for all threads to complete
	wg.Wait()

	elapsedtime := time.Since(starttime)
	fmt.Printf("[INFO] Test time was %v\n", elapsedtime)
}

func BenchmarkDomainRedirectSigner(b *testing.B) {
	if CA_CERT == nil {
		fmt.Printf("[ERROR] CA_CERT was nil.")
		os.Exit(1)
	}
	if CA_KEY == nil {
		fmt.Printf("[ERROR] CA_KEY was nil.")
		os.Exit(1)
	}
	err := LoadDefaultConfig()

	if err != nil {
		fmt.Printf("[ERROR] Couldn't load Default Config. err=%v\n", err)
		os.Exit(1)
	}
	if GoproxyCaConfig == nil {
		fmt.Printf("[ERROR] GoproxyCaConfig was nil.\n")
		os.Exit(1)
	}

	// Mercedes.com and latimes.com redirect to different sites. These appear to be holding up certificate requests.
	var domains []string = []string{"mercedes.com", "latimes.com"}
	var wg sync.WaitGroup
	b.ResetTimer()
	starttime := time.Now()

	for i := 0; i < 1; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 1; n++ {
				j := rand.Intn(len(domains))
				j = 0	// Just Mercedes

				fmt.Printf("[TEST] Starting certificate fetch for %s\n", domains[j])
				starttime := time.Now()
				GoproxyCaConfig.Cert(domains[j])


				certmu.RLock()

				tlsc, ok := GoproxyCaConfig.NameToCertificate[domains[j]]
				certmu.RUnlock()
				if !ok || tlsc == nil {
					fmt.Printf("[ERROR] Certificate fetch failed: %s\n", domains[j])
					//os.Exit(1)
				} else {
						fmt.Printf("[SUCCESS] Certificate fetch succeeded. : %s\n", domains[j])
				}
				elapsedtime := time.Since(starttime)
				fmt.Printf("[INFO] Fetch time for %s was %v\n", domains[j], elapsedtime)
			}
		}()
	}

	// Wait for all threads to complete
	wg.Wait()

	elapsedtime := time.Since(starttime)
	fmt.Printf("[INFO] Test time was %v\n", elapsedtime)
}



/*


import (
	//"crypto/tls"
	"crypto/x509"
	//"io/ioutil"
	"net/http"
	//"net/http/httptest"
	//"os"
	//"os/exec"
	"strings"
	"testing"
	//"time"
	. "github.com/smartystreets/goconvey/convey"
	"fmt"
)

func orFatal(msg string, err error, t *testing.T) {
	if err != nil {
		t.Fatal(msg, err)
	}
}

type ConstantHandler string

func (h ConstantHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(h))
}

func getBrowser(args []string) string {
	for i, arg := range args {
		if arg == "-browser" && i+1 < len(arg) {
			return args[i+1]
		}
		if strings.HasPrefix(arg, "-browser=") {
			return arg[len("-browser="):]
		}
	}
	return ""
}

// TODO: Refactor
func TestSigner(t *testing.T) {
	fmt.Println("TestSigner Start")
	LoadDefaultConfig()
	fmt.Println("TestSigner - Finished loading default config")

	Convey("TLS Certificate signing works", t, func() {
		fmt.Println()
		fmt.Println("TLS Certificate Signing Test")
		ca := GoproxyCaConfig
		// Generate a certificate
		err := ca.cert("example.com")
		So(err, ShouldEqual, nil)
		cert, ok := ca.NameToCertificate["example.com"]
		So(ok, ShouldEqual, true)
		So(cert, ShouldNotEqual, nil)

		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		So(err, ShouldEqual, nil)

		*/
/*expected := "key verifies with Go"
		server := httptest.NewUnstartedServer(ConstantHandler(expected))
		defer server.Close()
		//server.TLS = &tls.Config{Certificates: []tls.Certificate{*cert, *GoproxyCaConfig}}
		server.TLS = ca.Config
		server.TLS.BuildNameToCertificate()
		server.StartTLS()
		certpool := x509.NewCertPool()
		certpool.AddCert(cert.Leaf)
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certpool},
		}
		asLocalhost := strings.Replace(server.URL, "127.0.0.1", "localhost", -1)
		req, err := http.NewRequest("GET", asLocalhost, nil)
		So(err, ShouldEqual, nil)
		resp, err := tr.RoundTrip(req)
		So(err, ShouldEqual, nil)
		txt, err := ioutil.ReadAll(resp.Body)
		So(err, ShouldEqual, nil)
		if string(txt) != expected {
			t.Errorf("Expected '%s' got '%s'", expected, string(txt))
		}*//*



		//browser := getBrowser(os.Args)
		//if browser != "" {
		//	exec.Command(browser, asLocalhost).Run()
		//	time.Sleep(10 * time.Second)
		//}
	})

	*/
/*Convey("X509 certificates work", t, func() {
		ca := GoproxyCaConfig
		// Generate a certificate
		err := ca.cert("example.com")
		So(err, ShouldEqual, nil)
		cert, ok := ca.NameToCertificate["example.com"]
		So(ok, ShouldEqual, true)
		So(cert, ShouldNotEqual, nil)


		//cert, err := signHost(GoproxyCaConfig, []string{"example.com", "1.1.1.1", "localhost"})
		//orFatal("singHost", err, t)
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		So(err, ShouldEqual, nil)

		certpool := x509.NewCertPool()
		certpool.AddCert(cert.Leaf)
		//orFatal("VerifyHostname", cert.Leaf.VerifyHostname("example.com"), t)
		//orFatal("CheckSignatureFrom", cert.Leaf.CheckSignatureFrom(cert.Leaf), t)
		So(cert.Leaf.VerifyHostname("example.com"), ShouldEqual, true)
		So(cert.Leaf.CheckSignatureFrom(cert.Leaf), ShouldEqual, true)

		_, err = cert.Leaf.Verify(x509.VerifyOptions{
			DNSName: "example.com",
			Roots:   certpool,
		})
		So(err, ShouldEqual, nil)
	})*//*

}
*/
