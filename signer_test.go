package goproxy

import (
	"testing"
	"fmt"
	"os"
	"time"
	"sync"
	"math/rand"
	. "github.com/smartystreets/goconvey/convey"
	"crypto/x509"
	"net/http/httptest"
	"crypto/tls"
	"net/http"
	"strings"
	"io/ioutil"
	"github.com/valyala/fasthttp/fasthttputil"
	"github.com/inconshreveable/go-vhost"
	"context"
	"net"
	"io"
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

					tlsconfig, err := GoproxyCaConfig.Cert(domains[j])

					//tlsc, ok := GoproxyCaConfig.NameToCertificate[domains[j]]
					if err != nil || tlsconfig == nil {
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


				//certmu.RLock()
				//
				//tlsc, ok := GoproxyCaConfig.NameToCertificate[domains[j]]
				//certmu.RUnlock()
				tlsconfig, err := GoproxyCaConfig.Cert(domains[j])
				if err != nil || tlsconfig == nil {
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



type ConstantHandler string

func (h ConstantHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(h))
}

// Sets up a fake server having the given host name and simulates a client TLS request to it.
// The certificate is downloaded from the actual website.
//
// Returns:
// Read certificate: bool
// Handshake succeeded: bool
// Read body: bool
// Body: []byte
func simulateHttpsRequest(host string) (bool, bool, bool, []byte) {
	// Preload the cert cache
	tlsconfig, err := GoproxyCaConfig.certWithCommonName(host, "443")

	if tlsconfig == nil || err != nil {
		fmt.Printf("[TEST] Unexpected error - couldn't fetch certificate.")
		return false, false, false, nil
	}

	expected := "WINSTON OK"
	// To use a domain name other than localhost, we have to set up a pipe and manage the connection ourselves.
	var pipe *fasthttputil.PipeConns
	pipe = fasthttputil.NewPipeConns()

	// Client needs the public key of the cert
	// This confirms that the certificate works for the SAN host.
	cert, ok := tlsconfig.NameToCertificate[host]
	So(ok, ShouldEqual, true)
	So(cert, ShouldNotEqual, nil)
	certpool := x509.NewCertPool()
	certpool.AddCert(cert.Leaf)

	fakeclient := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certpool,
				InsecureSkipVerify: false,
			},
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				return pipe.Conn1(), nil
			},
		},
	}

	// Simulate a listener (server)
	var wg sync.WaitGroup
	wg.Add(1)
	var handshakesucceeded bool
	go func() {
		defer wg.Done()
		// We'll serve the original microsoft.com certificate to the myservice.xbox.com domain.
		tlsconfig, err := GoproxyCaConfig.certWithCommonName(host, "443")

		tlsConnClient, err := vhost.TLS(pipe.Conn2())
		timeoutDuration := time.Duration(5) * time.Second
		if err != nil {
			fmt.Printf("[ERROR] Server couldn't open pipe to fake client. Unmodified https response not available. $+v\n", err)
			os.Exit(1)
		}

		tlsConnClient.SetReadDeadline(time.Now().Add(timeoutDuration))
		tlsConnClient.SetWriteDeadline(time.Now().Add(timeoutDuration))

		rawClientTls := tls.Server(tlsConnClient, tlsconfig)
		rawClientTls.SetReadDeadline(time.Now().Add(timeoutDuration))
		rawClientTls.SetWriteDeadline(time.Now().Add(timeoutDuration))

		err = rawClientTls.Handshake()
		if err==nil {
			handshakesucceeded = true

			// Return a string so we can confirm it worked
			io.WriteString(rawClientTls, "HTTP/1.1 200 OK\r\n\r\n")
			io.WriteString(rawClientTls, expected)
			fmt.Printf("[TEST] Server wrote to client: [%s]\n", expected)

			// Give it some time to complete or we may close the connection before the body can be read.
			time.Sleep(500 * time.Millisecond)

		} /*else {
				fmt.Printf("[TEST] Handshake failed: %v\n", err)
			}*/

		tlsConnClient.Close()
		rawClientTls.Close()
	}()

	// Initiate a request. This must be done in a new goroutine so the handshakes can complete.
	// We don't care about sending valid headers or what the response is.
	var readbody bool
	var body []byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		request, _ := http.NewRequest("GET", "https://" + host + ":443", nil)

		// Perform TLS handshake, read body and ensure it's what we expected.
		resp, err := fakeclient.Do(request)
		if resp != nil && err == nil {
			body, err = ioutil.ReadAll(resp.Body)
			if err == nil {
				fmt.Printf("[TEST] Client read body [%s]\n", string(body))
				if string(body) == expected {
					readbody = true
				}
			} else {
				//fmt.Printf("[TEST] Couldn't read body. err=%v\n", err)
			}
			resp.Body.Close()
		} else {
			//fmt.Printf("[TEST] No response received by client. err=%v\n", err)
		}

	}()

	// Wait until they complete
	wg.Wait()

	return true, handshakesucceeded, readbody, body

}

func TestSigner(t *testing.T) {
	LoadDefaultConfig()

	if true {

		Convey("Expired SSL certificates are rejected", t, func() {
			host := "expired.badssl.com"

			So (CA_CERT, ShouldNotEqual, nil)
			So (CA_KEY, ShouldNotEqual, nil)
			So(GoproxyCaConfig, ShouldNotEqual, nil)


			// Test that encrypted tunnel can be established to SANHost using the cached certificate
			fmt.Println()
			fmt.Printf("[TEST] Starting expired certificate test\n")

			readcertificate, handshakesucceeded, readbody, _ := simulateHttpsRequest(host)

			So(readcertificate, ShouldEqual, true)
			So(handshakesucceeded, ShouldEqual, false)
			So(readbody, ShouldEqual, false)

		})

		/*Convey("FlushCert removes related domains from certificate cache", t, func() {
			// Microsoft.com cert contains SAN for *.microsoftitacademy.com as of 10/19/2018
			// Note that it does not contain microsoftitacademy.com so this ensures we don't
			// fall back on an exact match.
			host := "microsoft.com"
			SANhost := "microsoftitacademy.com"

			So (CA_CERT, ShouldNotEqual, nil)
			So (CA_KEY, ShouldNotEqual, nil)
			So(GoproxyCaConfig, ShouldNotEqual, nil)

			// Clear out the cache so other tests don't interfere
			GoproxyCaConfig.Host = make(map[string]*HostInfo)

			// Download the certificate
			tlsconfig, err := GoproxyCaConfig.certWithCommonName(host, "443")
			So(err, ShouldEqual, nil)
			So(tlsconfig, ShouldNotEqual, nil)

			// There are lots of domains on this certificate
			So(len(GoproxyCaConfig.Host), ShouldBeGreaterThan, 20)

			fmt.Printf("[TEST] Len before Flushcert: %d\n", len(GoproxyCaConfig.Host))
			GoproxyCaConfig.FlushCert(SANhost)
			fmt.Printf("[TEST] Len after Flushcert: %d\n", len(GoproxyCaConfig.Host))
			So(len(GoproxyCaConfig.Host), ShouldEqual, 0)


		})*/

		/*Convey("TLD+1 matches wildcard SAN", t, func() {
			// Microsoft.com cert contains SAN for *.microsoftitacademy.com as of 10/19/2018
			// Note that it does not contain microsoftitacademy.com so this ensures we don't
			// fall back on an exact match.
			host := "microsoft.com"
			SANhost := "microsoftitacademy.com"

			So (CA_CERT, ShouldNotEqual, nil)
			So (CA_KEY, ShouldNotEqual, nil)
			So(GoproxyCaConfig, ShouldNotEqual, nil)

			// Ensure we can communicate using the new certificate
			// Server needs the cert for the requested domain as well as its own private key (root cert)
			tlsconfig, err := GoproxyCaConfig.certWithCommonName(host, "443")
			So(err, ShouldEqual, nil)
			So(tlsconfig, ShouldNotEqual, nil)

			cert, ok := tlsconfig.NameToCertificate[host]
			So(ok, ShouldEqual, true)
			So(cert, ShouldNotEqual, nil)

			cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
			So(err, ShouldEqual, nil)
			serial := cert.Leaf.SerialNumber.String()

			// This domain doesn't exist, so it shouldn't be in the cert cache
			_, found := GoproxyCaConfig.Host[SANhost]
			So(found, ShouldEqual, false)

			fmt.Println()
			fmt.Println("[TEST] Starting wildcard lookup")
			// Serial # of wildcard domain should match. This domain is invalid, so would get an error otherwise.
			tlsconfig, err = GoproxyCaConfig.certWithCommonName(SANhost, "443")
			So(err, ShouldEqual, nil)
			So(tlsconfig, ShouldNotEqual, nil)

			// We only have one valid certificate so just grab the first one.
			randomkey := ""
			for k, _ := range tlsconfig.NameToCertificate {
				randomkey = k
				break
			}
			cert, ok = tlsconfig.NameToCertificate[randomkey]

			So(ok, ShouldEqual, true)
			So(cert, ShouldNotEqual, nil)

			cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
			So(err, ShouldEqual, nil)
			serialSAN := cert.Leaf.SerialNumber.String()

			So(serial, ShouldEqual, serialSAN)

		})*/

		/*Convey("subdomain matches wildcard SAN", t, func() {
			// Microsoft.com cert contains SAN for *.microsoftitacademy.com as of 10/19/2018
			// Note that it does not contain microsoftitacademy.com so this ensures we don't
			// fall back on an exact match.
			host := "microsoft.com"
			SANhost := "subdomain.microsoftitacademy.com"

			So (CA_CERT, ShouldNotEqual, nil)
			So (CA_KEY, ShouldNotEqual, nil)
			So(GoproxyCaConfig, ShouldNotEqual, nil)

			// Ensure we can communicate using the new certificate
			// Server needs the cert for the requested domain as well as its own private key (root cert)
			tlsconfig, err := GoproxyCaConfig.certWithCommonName(host, "443")
			So(err, ShouldEqual, nil)
			So(tlsconfig, ShouldNotEqual, nil)

			cert, ok := tlsconfig.NameToCertificate[host]
			So(ok, ShouldEqual, true)
			So(cert, ShouldNotEqual, nil)

			cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
			So(err, ShouldEqual, nil)
			serial := cert.Leaf.SerialNumber.String()

			// This domain doesn't exist, so it shouldn't be in the cert cache
			_, found := GoproxyCaConfig.Host[SANhost]
			So(found, ShouldEqual, false)

			fmt.Println()
			fmt.Println("[TEST] Starting wildcard lookup")
			// Serial # of wildcard domain should match. This domain is invalid, so would get an error otherwise.
			tlsconfig, err = GoproxyCaConfig.certWithCommonName(SANhost, "443")
			So(err, ShouldEqual, nil)
			So(tlsconfig, ShouldNotEqual, nil)

			// We only have one valid certificate so just grab the first one.
			randomkey := ""
			for k, _ := range tlsconfig.NameToCertificate {
				randomkey = k
				break
			}
			cert, ok = tlsconfig.NameToCertificate[randomkey]

			So(ok, ShouldEqual, true)
			So(cert, ShouldNotEqual, nil)

			cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
			So(err, ShouldEqual, nil)
			serialSAN := cert.Leaf.SerialNumber.String()

			So(serial, ShouldEqual, serialSAN)

		})*/

		/*Convey("Two level subdomain matches wildcard SAN", t, func() {
			// Microsoft.com cert contains SAN for *.microsoftitacademy.com as of 10/19/2018
			// Note that it does not contain microsoftitacademy.com so this ensures we don't
			// fall back on an exact match.
			host := "microsoft.com"
			SANhost := "123.abcd.microsoftitacademy.com"

			So (CA_CERT, ShouldNotEqual, nil)
			So (CA_KEY, ShouldNotEqual, nil)
			So(GoproxyCaConfig, ShouldNotEqual, nil)

			// Ensure we can communicate using the new certificate
			// Server needs the cert for the requested domain as well as its own private key (root cert)
			tlsconfig, err := GoproxyCaConfig.certWithCommonName(host, "443")
			So(err, ShouldEqual, nil)
			So(tlsconfig, ShouldNotEqual, nil)

			cert, ok := tlsconfig.NameToCertificate[host]
			So(ok, ShouldEqual, true)
			So(cert, ShouldNotEqual, nil)

			cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
			So(err, ShouldEqual, nil)
			serial := cert.Leaf.SerialNumber.String()

			// This domain doesn't exist, so it shouldn't be in the cert cache
			_, found := GoproxyCaConfig.Host[SANhost]
			So(found, ShouldEqual, false)

			fmt.Println()
			fmt.Println("[TEST] Starting wildcard lookup")
			// Serial # of wildcard domain should match. This domain is invalid, so would get an error otherwise.
			tlsconfig, err = GoproxyCaConfig.certWithCommonName(SANhost, "443")
			So(err, ShouldEqual, nil)
			So(tlsconfig, ShouldNotEqual, nil)

			// We only have one valid certificate so just grab the first one.
			randomkey := ""
			for k, _ := range tlsconfig.NameToCertificate {
				randomkey = k
				break
			}
			cert, ok = tlsconfig.NameToCertificate[randomkey]

			So(ok, ShouldEqual, true)
			So(cert, ShouldNotEqual, nil)

			cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
			So(err, ShouldEqual, nil)
			serialSAN := cert.Leaf.SerialNumber.String()

			So(serial, ShouldEqual, serialSAN)

		})*/

		/*Convey("Can establish TLS tunnel for wildcard domains listed in SAN extension", t, func() {
			// Microsoft.com cert contains SAN for xbox.com as of 10/19/2018
			host := "microsoft.com"
			SANhost := "somedomain.microsoftitacademy.com"

			So (CA_CERT, ShouldNotEqual, nil)
			So (CA_KEY, ShouldNotEqual, nil)
			So(GoproxyCaConfig, ShouldNotEqual, nil)


			// Preload the cert cache
			tlsconfig, err := GoproxyCaConfig.certWithCommonName(host, "443")
			So(err, ShouldEqual, nil)
			So(tlsconfig, ShouldNotEqual, nil)



			// Test that encrypted tunnel can be established to SANHost using the cached certificate
			//fmt.Println()
			//fmt.Printf("[TEST] Starting handshake test\n")

			expected := "WINSTON OK"
			// To use a domain name other than localhost, we have to set up a pipe and manage the connection ourselves.
			var pipe *fasthttputil.PipeConns
			pipe = fasthttputil.NewPipeConns()

			// Client needs the public key of the cert
			// This confirms that the certificate works for the SAN host.
			// Note that we just use the non-wildcard version for convenience.
			cert, ok := tlsconfig.NameToCertificate[host]
			So(ok, ShouldEqual, true)
			So(cert, ShouldNotEqual, nil)
			certpool := x509.NewCertPool()
			certpool.AddCert(cert.Leaf)

			fakeclient := http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs: certpool,
						InsecureSkipVerify: false,
					},
					DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
						return pipe.Conn1(), nil
					},
				},
			}

			// Simulate a listener (server)
			var wg sync.WaitGroup
			wg.Add(1)
			var handshakesucceeded bool
			go func() {
				defer wg.Done()
				// We'll serve the original microsoft.com certificate to the myservice.xbox.com domain.
				tlsconfig, err := GoproxyCaConfig.certWithCommonName(host, "443")

				tlsConnClient, err := vhost.TLS(pipe.Conn2())
				timeoutDuration := time.Duration(5) * time.Second
				if err != nil {
					fmt.Printf("[ERROR] Server couldn't open pipe to fake client. Unmodified https response not available. $+v\n", err)
					os.Exit(1)
				}

				tlsConnClient.SetReadDeadline(time.Now().Add(timeoutDuration))
				tlsConnClient.SetWriteDeadline(time.Now().Add(timeoutDuration))

				rawClientTls := tls.Server(tlsConnClient, tlsconfig)
				rawClientTls.SetReadDeadline(time.Now().Add(timeoutDuration))
				rawClientTls.SetWriteDeadline(time.Now().Add(timeoutDuration))

				err = rawClientTls.Handshake()
				if err==nil {
					handshakesucceeded = true

					// Return a string so we can confirm it worked
					io.WriteString(rawClientTls, "HTTP/1.1 200 OK\r\n\r\n")
					io.WriteString(rawClientTls, expected)
					//fmt.Printf("[TEST] Server wrote to client: [%s]\n", expected)

					// Give it some time to complete or we may close the connection before the body can be read.
					time.Sleep(500 * time.Millisecond)

				} else {
					fmt.Printf("[TEST] Handshake failed: %v\n", err)
				}

				tlsConnClient.Close()
				rawClientTls.Close()
			}()

			// Initiate a request. This must be done in a new goroutine so the handshakes can complete.
			// We don't care about sending valid headers or what the response is.
			var readbody bool
			wg.Add(1)
			go func() {
				defer wg.Done()
				request, _ := http.NewRequest("GET", "https://" + SANhost + ":443", nil)

				//fmt.Printf("[INFO] Making fake request to %s\n", SANhost)

				// Perform TLS handshake, read body and ensure it's what we expected.
				resp, err := fakeclient.Do(request)
				if resp != nil && err == nil {
					body, err := ioutil.ReadAll(resp.Body)
					if err == nil {
						//fmt.Printf("[TEST] Client read body [%s]\n", string(body))
						if string(body) == expected {
							readbody = true
						}
					} else {
						fmt.Printf("[TEST] Couldn't read body. err=%v\n", err)
					}
					resp.Body.Close()
				} else {
					fmt.Printf("[TEST] No response received by client. err=%v\n", err)
				}

			}()

			// Wait until they complete
			wg.Wait()

			So(handshakesucceeded, ShouldEqual, true)
			So(readbody, ShouldEqual, true)

		})*/

		/*Convey("Can establish TLS tunnel for domains listed in SAN extension", t, func() {
			// Microsoft.com cert contains SAN for xbox.com as of 10/19/2018
			host := "microsoft.com"
			SANhost := "myservice.xbox.com"

			So (CA_CERT, ShouldNotEqual, nil)
			So (CA_KEY, ShouldNotEqual, nil)
			So(GoproxyCaConfig, ShouldNotEqual, nil)


			// Preload the cert cache
			tlsconfig, err := GoproxyCaConfig.certWithCommonName(host, "443")
			So(err, ShouldEqual, nil)
			So(tlsconfig, ShouldNotEqual, nil)



			// Test that encrypted tunnel can be established to SANHost using the cached certificate
			//fmt.Println()
			//fmt.Printf("[TEST] Starting handshake test\n")

			expected := "WINSTON OK"
			// To use a domain name other than localhost, we have to set up a pipe and manage the connection ourselves.
			var pipe *fasthttputil.PipeConns
			pipe = fasthttputil.NewPipeConns()

			// Client needs the public key of the cert
			// This confirms that the certificate works for the SAN host.
			cert, ok := tlsconfig.NameToCertificate[SANhost]
			So(ok, ShouldEqual, true)
			So(cert, ShouldNotEqual, nil)
			certpool := x509.NewCertPool()
			certpool.AddCert(cert.Leaf)

			fakeclient := http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs: certpool,
						InsecureSkipVerify: false,
					},
					DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
						return pipe.Conn1(), nil
					},
				},
			}

			// Simulate a listener (server)
			var wg sync.WaitGroup
			wg.Add(1)
			var handshakesucceeded bool
			go func() {
				defer wg.Done()
				// We'll serve the original microsoft.com certificate to the myservice.xbox.com domain.
				tlsconfig, err := GoproxyCaConfig.certWithCommonName(host, "443")

				tlsConnClient, err := vhost.TLS(pipe.Conn2())
				timeoutDuration := time.Duration(5) * time.Second
				if err != nil {
					fmt.Printf("[ERROR] Server couldn't open pipe to fake client. Unmodified https response not available. $+v\n", err)
					os.Exit(1)
				}

				tlsConnClient.SetReadDeadline(time.Now().Add(timeoutDuration))
				tlsConnClient.SetWriteDeadline(time.Now().Add(timeoutDuration))

				rawClientTls := tls.Server(tlsConnClient, tlsconfig)
				rawClientTls.SetReadDeadline(time.Now().Add(timeoutDuration))
				rawClientTls.SetWriteDeadline(time.Now().Add(timeoutDuration))

				err = rawClientTls.Handshake()
				if err==nil {
					handshakesucceeded = true

					// Return a string so we can confirm it worked
					io.WriteString(rawClientTls, "HTTP/1.1 200 OK\r\n\r\n")
					io.WriteString(rawClientTls, expected)
					//fmt.Printf("[TEST] Server wrote to client: [%s]\n", expected)

					// Give it some time to complete or we may close the connection before the body can be read.
					time.Sleep(500 * time.Millisecond)

				} else {
					fmt.Printf("[TEST] Handshake failed: %v\n", err)
				}

				tlsConnClient.Close()
				rawClientTls.Close()
			}()

			// Initiate a request. This must be done in a new goroutine so the handshakes can complete.
			// We don't care about sending valid headers or what the response is.
			var readbody bool
			wg.Add(1)
			go func() {
				defer wg.Done()
				request, _ := http.NewRequest("GET", "https://" + SANhost + ":443", nil)

				//fmt.Printf("[INFO] Making fake request to %s\n", SANhost)

				// Perform TLS handshake, read body and ensure it's what we expected.
				resp, err := fakeclient.Do(request)
				if resp != nil && err == nil {
					body, err := ioutil.ReadAll(resp.Body)
					if err == nil {
						//fmt.Printf("[TEST] Client read body [%s]\n", string(body))
						if string(body) == expected {
							readbody = true
						}
					} else {
						fmt.Printf("[TEST] Couldn't read body. err=%v\n", err)
					}
					resp.Body.Close()
				} else {
					fmt.Printf("[TEST] No response received by client. err=%v\n", err)
				}

			}()

			// Wait until they complete
			wg.Wait()

			So(handshakesucceeded, ShouldEqual, true)
			So(readbody, ShouldEqual, true)

		})*/

		/*Convey("Cannot establish TLS tunnel for domains not listed in SAN extension", t, func() {
			// Microsoft.com cert contains SAN for xbox.com as of 10/19/2018
			host := "microsoft.com"
			SANhost := "myservice.xbox.com"
			Badhost := "twitter.com"

			So (CA_CERT, ShouldNotEqual, nil)
			So (CA_KEY, ShouldNotEqual, nil)
			So(GoproxyCaConfig, ShouldNotEqual, nil)


			// Preload the cert cache
			tlsconfig, err := GoproxyCaConfig.certWithCommonName(host, "443")
			So(err, ShouldEqual, nil)
			So(tlsconfig, ShouldNotEqual, nil)



			// Test that encrypted tunnel can be established to SANHost using the cached certificate
			//fmt.Println()
			//fmt.Printf("[TEST] Starting bad handshake test\n")

			expected := "WINSTON OK"
			// To use a domain name other than localhost, we have to set up a pipe and manage the connection ourselves.
			var pipe *fasthttputil.PipeConns
			pipe = fasthttputil.NewPipeConns()

			// Client needs the public key of the cert
			// This confirms that the certificate works for the SAN host.
			cert, ok := tlsconfig.NameToCertificate[SANhost]
			So(ok, ShouldEqual, true)
			So(cert, ShouldNotEqual, nil)
			certpool := x509.NewCertPool()
			certpool.AddCert(cert.Leaf)

			fakeclient := http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs: certpool,
						InsecureSkipVerify: false,
					},
					DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
						return pipe.Conn1(), nil
					},
				},
			}

			// Simulate a listener (server)
			var wg sync.WaitGroup
			wg.Add(1)
			var handshakesucceeded bool
			go func() {
				defer wg.Done()
				// We'll serve the original microsoft.com certificate to the myservice.xbox.com domain.
				tlsconfig, err := GoproxyCaConfig.certWithCommonName(host, "443")

				tlsConnClient, err := vhost.TLS(pipe.Conn2())
				timeoutDuration := time.Duration(5) * time.Second
				if err != nil {
					fmt.Printf("[ERROR] Server couldn't open pipe to fake client. Unmodified https response not available. $+v\n", err)
					os.Exit(1)
				}

				tlsConnClient.SetReadDeadline(time.Now().Add(timeoutDuration))
				tlsConnClient.SetWriteDeadline(time.Now().Add(timeoutDuration))

				rawClientTls := tls.Server(tlsConnClient, tlsconfig)
				rawClientTls.SetReadDeadline(time.Now().Add(timeoutDuration))
				rawClientTls.SetWriteDeadline(time.Now().Add(timeoutDuration))

				err = rawClientTls.Handshake()
				if err==nil {
					handshakesucceeded = true

					// Return a string so we can confirm it worked
					io.WriteString(rawClientTls, "HTTP/1.1 200 OK\r\n\r\n")
					io.WriteString(rawClientTls, expected)
					fmt.Printf("[TEST] Server wrote to client: [%s]\n", expected)

					// Give it some time to complete or we may close the connection before the body can be read.
					time.Sleep(500 * time.Millisecond)

				} *//*else {
				fmt.Printf("[TEST] Handshake failed: %v\n", err)
			}*//*

				tlsConnClient.Close()
				rawClientTls.Close()
			}()

			// Initiate a request. This must be done in a new goroutine so the handshakes can complete.
			// We don't care about sending valid headers or what the response is.
			var readbody bool
			wg.Add(1)
			go func() {
				defer wg.Done()
				request, _ := http.NewRequest("GET", "https://" + Badhost + ":443", nil)

				//fmt.Printf("[INFO] Making fake request to %s\n", Badhost)

				// Perform TLS handshake, read body and ensure it's what we expected.
				resp, err := fakeclient.Do(request)
				if resp != nil && err == nil {
					body, err := ioutil.ReadAll(resp.Body)
					if err == nil {
						fmt.Printf("[TEST] Client read body [%s]\n", string(body))
						if string(body) == expected {
							readbody = true
						}
					} else {
						//fmt.Printf("[TEST] Couldn't read body. err=%v\n", err)
					}
					resp.Body.Close()
				} else {
					//fmt.Printf("[TEST] No response received by client. err=%v\n", err)
				}

			}()

			// Wait until they complete
			wg.Wait()

			So(handshakesucceeded, ShouldEqual, false)
			So(readbody, ShouldEqual, false)

		})*/


		Convey("Can retrieve valid certificate", t, func() {
			So(CA_CERT, ShouldNotEqual, nil)
			So(CA_KEY, ShouldNotEqual, nil)
			So(GoproxyCaConfig, ShouldNotEqual, nil)

			tlsconfig, err := GoproxyCaConfig.Cert("twitter.com")
			So(err, ShouldEqual, nil)
			So(tlsconfig, ShouldNotEqual, nil)
			//fmt.Printf("[TEST] tlsconfig = %+v\n", tlsconfig)

			// TODO: Retrieve a page with the new certificate?

			cert, ok := tlsconfig.NameToCertificate["twitter.com"]
			So(ok, ShouldEqual, true)
			So(cert, ShouldNotEqual, nil)

			cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
			So(err, ShouldEqual, nil)

			// Get another certificate and ensure the first cert isn't in its dictionary.
			tlsconfig2, err := GoproxyCaConfig.Cert("facebook.com")
			So(err, ShouldEqual, nil)
			So(tlsconfig2, ShouldNotEqual, nil)
			cert2, ok := tlsconfig2.NameToCertificate["twitter.com"]
			So(ok, ShouldEqual, false)
			So(cert2, ShouldEqual, nil)

		})

		Convey("Can establish TLS connection using self-signed MITM certificates", t, func() {
			So(CA_CERT, ShouldNotEqual, nil)
			So(CA_KEY, ShouldNotEqual, nil)
			So(GoproxyCaConfig, ShouldNotEqual, nil)


			// Ensure we can communicate using the new certificate
			// Server needs the cert for the requested domain as well as its own private key (root cert)
			tlsconfig, err := GoproxyCaConfig.GetTestCertificate("localhost", "443")
			So(err, ShouldEqual, nil)
			So(tlsconfig, ShouldNotEqual, nil)

			cert, ok := tlsconfig.NameToCertificate["localhost"]
			So(ok, ShouldEqual, true)
			So(cert, ShouldNotEqual, nil)

			cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
			So(err, ShouldEqual, nil)

			expected := "key verifies with Go"
			server := httptest.NewUnstartedServer(ConstantHandler(expected))
			defer server.Close()
			server.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}        //, *GoproxyCaConfig
			//server.TLS = ca.Config
			server.TLS.BuildNameToCertificate()
			server.StartTLS()

			// Client needs the public key of the cert
			certpool := x509.NewCertPool()
			certpool.AddCert(cert.Leaf)
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: certpool},
				//Proxy: http.ProxyURL(proxyUrl),
			}
			asLocalhost := strings.Replace(server.URL, "127.0.0.1", "localhost", -1)
			//fmt.Printf("[TEST] asLocalhost: %s\n", asLocalhost)
			req, err := http.NewRequest("GET", asLocalhost, nil)
			So(err, ShouldEqual, nil)
			resp, err := tr.RoundTrip(req)
			So(err, ShouldEqual, nil)
			txt, err := ioutil.ReadAll(resp.Body)
			So(err, ShouldEqual, nil)
			So(string(txt), ShouldEqual, expected)
		})

		// It is critical that this test passes, otherwise cached certificates will never be used.
		// Note that we don't fully support all verify methods and most will fail.
		Convey("Basic x509 verification works", t, func() {
			So(CA_CERT, ShouldNotEqual, nil)
			So(CA_KEY, ShouldNotEqual, nil)
			So(GoproxyCaConfig, ShouldNotEqual, nil)

			ca := GoproxyCaConfig
			// Generate a certificate
			tlsconfig, err := ca.cert("microsoft.com")
			So(err, ShouldEqual, nil)
			So(tlsconfig, ShouldNotEqual, nil)

			cert, ok := tlsconfig.NameToCertificate["microsoft.com"]
			So(ok, ShouldEqual, true)
			So(cert, ShouldNotEqual, nil)

			//cert, err := signHost(GoproxyCaConfig, []string{"example.com", "1.1.1.1", "localhost"})
			//orFatal("singHost", err, t)
			cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
			So(err, ShouldEqual, nil)
			//fmt.Printf("[TEST] cert.Leaf=%+v\n", cert.Leaf)
			//certpool := x509.NewCertPool()
			//certpool.AddCert(cert.Leaf)
			//verified, err := cert.Leaf.VerifyHostname("twitter.com")
			_, err = cert.Leaf.Verify(x509.VerifyOptions{
				DNSName: "microsoft.com",
				Roots:   GoproxyCaConfig.RootCAs,
			})
			So(err, ShouldEqual, nil)

			// Original Elazarl unit tests had this. Was not working in goproxy. Haven't found a reason we
			// need to support this call yet.
			//fmt.Println()
			//fmt.Println("[TEST] CheckSignatureFrom...")

			//So(cert.Leaf.CheckSignatureFrom(cert.Leaf), ShouldEqual, true)

		})

		Convey("Certificates are cached", t, func() {
			So(CA_CERT, ShouldNotEqual, nil)
			So(CA_KEY, ShouldNotEqual, nil)
			So(GoproxyCaConfig, ShouldNotEqual, nil)

			tlsconfig, err := GoproxyCaConfig.Cert("twitter.com")
			So(err, ShouldEqual, nil)
			So(tlsconfig, ShouldNotEqual, nil)
			//fmt.Printf("[TEST] tlsconfig = %+v\n", tlsconfig)

			// TODO: Retrieve a page with the new certificate?

			cert, ok := tlsconfig.NameToCertificate["twitter.com"]
			So(ok, ShouldEqual, true)
			So(cert, ShouldNotEqual, nil)

			cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])

			// Note: x509 serial numbers are *big.Int so you can't compare them directly.
			// They must be converted to strings first.
			serial := cert.Leaf.SerialNumber.String()

			cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
			So(err, ShouldEqual, nil)

			// Get another certificate and ensure the first cert isn't in its dictionary.
			tlsconfig2, err := GoproxyCaConfig.Cert("twitter.com")
			So(err, ShouldEqual, nil)
			So(tlsconfig2, ShouldNotEqual, nil)
			cert2, ok := tlsconfig2.NameToCertificate["twitter.com"]
			So(ok, ShouldEqual, true)
			So(cert2, ShouldNotEqual, nil)

			cert2.Leaf, err = x509.ParseCertificate(cert2.Certificate[0])
			serial2 := cert2.Leaf.SerialNumber.String()

			So(serial2, ShouldEqual, serial)
		})
	}


}
