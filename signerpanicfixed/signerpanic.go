/* Reproduces WINSTON-379 - Hashmap collision panics during TLS handshake.
 */
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	//"strings"
	"sync"
	"time"
	"fmt"
	"os"
	"net/http"
	"context"
	//"strconv"
	//"io/ioutil"
	"github.com/hashicorp/go-rootcerts"
	"github.com/valyala/fasthttp/fasthttputil"
	"github.com/inconshreveable/go-vhost"
	random "math/rand"
)

var TestCaConfig *GoproxyConfigServer

func main() {
	err := LoadDefaultConfig()
	if err != nil || TestCaConfig == nil {
		fmt.Printf("[ERROR] Couldn't load Default Config. err=%v\n", err)
		os.Exit(1)
	}

	var domains []string = []string{"twitter.com", "nbc.com", "mercedes-benz.com", "google.com", "facebook.com", "nytimes.com", "washingtonpost.com", "www.latimes.com", "politico.com",
		"drudgereport.com", "microsoft.com", "windows.com", "mcdonalds.com", "winstonprivacy.com", "shopify.com",
		"theguardian.com", "digg.com", "reddit.com", "myspace.com", "wsj.com", "twobithistory.org", "mozilla.org", "youtube.com", "cloudflare.net",
		"sprint.com", "verizon.com"}

	// Load up the certificates
	fmt.Printf("[INFO] Prefetching certificates.\n")
	for j := 0; j < len(domains); j++ {
		TestCaConfig.Cert(domains[j])
	}

	// Spin up a go routine to constantly retrieve the same set of certificates.
	go func() {
		for {
			// Get a random certificate
			j := random.Intn(len(domains))
			TestCaConfig.Cert(domains[j])
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Goroutine to continually simulate incoming client TLS connections
	var wgmain sync.WaitGroup
	wgmain.Add(1)
	go func() {
		defer wgmain.Done()
		for i := 0; i < 500; i++ {
			var wg sync.WaitGroup
			j := random.Intn(len(domains))
			var host string
			host = domains[j]

			// Simulate an inbound TLS request using a piped connection.
			var pipe *fasthttputil.PipeConns
			pipe = fasthttputil.NewPipeConns()

			fakeclient := http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
					DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
						return pipe.Conn1(), nil
					},
				},
			}

			// Simulate a listener (server)
			wg.Add(1)
			go func() {
				defer wg.Done()
				tlsConfig, err := tlsConfig(host)

				tlsConnClient, err := vhost.TLS(pipe.Conn2())
				timeoutDuration := time.Duration(5) * time.Second
				if err != nil {
					fmt.Printf("[ERROR] Server couldn't open pipe to fake client. Unmodified https response not available. $+v\n", err)
					os.Exit(1)
				}

				tlsConnClient.SetReadDeadline(time.Now().Add(timeoutDuration))
				tlsConnClient.SetWriteDeadline(time.Now().Add(timeoutDuration))

				rawClientTls := tls.Server(tlsConnClient, tlsConfig)
				rawClientTls.SetReadDeadline(time.Now().Add(timeoutDuration))
				rawClientTls.SetWriteDeadline(time.Now().Add(timeoutDuration))

				if err := rawClientTls.Handshake(); err != nil {
					fmt.Printf("[ERROR] Server handshake to %s failed. err=%v\n", host, err)
				} else {
					fmt.Printf("[OK] Server handshake to %s completed successfully.\n", host)
				}
				tlsConnClient.Close()
				rawClientTls.Close()
			}()

			// Initiate a request. This must be done in a new goroutine so the handshakes can complete.
			// We don't care about sending valid headers or what the response is.
			wg.Add(1)
			go func() {
				defer wg.Done()
				request, _ := http.NewRequest("GET", "https://" + host + ":443", nil)

				fmt.Printf("[INFO] Making fake request to %s\n", host)

				// This request won't complete because the fake server doesn't return anything.
				fakeclient.Do(request)

				// Ignore and continue.
			}()

			// Wait until they complete
			wg.Wait()
			fmt.Printf("[INFO] TLS Handshake completed to %s\n", host)

		}
	}()

	wgmain.Wait()

}

func tlsConfig(host string) (*tls.Config, error) {
	// Ensure that the tls config for the target site has been generated
	config, err := TestCaConfig.cert(host)
	if err != nil {
		fmt.Printf("[DEBUG] Certificate signing error [%s] %+v\n", host, err)
		return nil, err
	}

	return config, nil
}



// OrganizationName is the name your CA cert will be signed with. It
// will show in your different UIs. Change it globally here to show
// meaningful things to your users.
var OrganizationName = "Winston Privacy"

// MaxSerialNumber is the upper boundary that is used to create unique serial
// numbers for the certificate. This can be any unsigned integer up to 20
// bytes (2^(8*20)-1).
var MaxSerialNumber = big.NewInt(0).SetBytes(bytes.Repeat([]byte{255}, 20))

// Global lock on the certificate store.
var certmu          	sync.RWMutex

// Stores metadata about a particular host. Used to improve performance.
type HostInfo struct {
	LastVerify 	time.Time
	NextAttempt	time.Time	// Set to future time for invalid certs to avoid frequent reloading
	mu 		sync.Mutex
	Config		*tls.Config
}

// Config is a set of configuration values that are used to build TLS configs
// capable of MITM.
// Maintains a global list of immutable TLS Configs which can be used for TLS handshakes.
type GoproxyConfigServer struct {
	Root            *x509.Certificate
	RootCAs		*x509.CertPool
	capriv          interface{}
	priv            *rsa.PrivateKey
	keyID           []byte
	validity        time.Duration
				    //*tls.Config
	bypassDnsDialer *net.Dialer // Custom DNS resolver
	Host		map[string]*HostInfo
				    //Config		map[string]
}

// NewConfig creates a MITM config using the CA certificate and
// private key to generate on-the-fly certificates.
func NewConfigServer(filename string, ca *x509.Certificate, privateKey interface{}) (*GoproxyConfigServer, error) {
	var priv *rsa.PrivateKey
	var err error

	// Must set in order to self-sign x509 certificates.
	ca.BasicConstraintsValid = true
	ca.IsCA = true
	//ca.KeyUsage = x509.KeyUsageCertSign
	ca.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	ca.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	priv, err = rsa.GenerateKey(rand.Reader, 2048)



	if err != nil {
		return nil, err
	}
	pub := priv.Public()

	// Subject Key Identifier support for end entity certificate.
	// https://www.ietf.org/rfc/rfc3280.txt (section 4.2.1.2)
	pkixpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	h := sha1.New()
	h.Write(pkixpub)
	keyID := h.Sum(nil)

	tlsConfigServer := &GoproxyConfigServer{
		Root:     		ca,
		capriv:   		privateKey,
		priv:     		priv,
		keyID:    		keyID,
		validity: 		time.Hour * 24 * 3650,
		Host:     		make(map[string]*HostInfo),
		RootCAs:		x509.NewCertPool(),
	}


	if tlsConfigServer.RootCAs == nil {
		tlsConfigServer.RootCAs = x509.NewCertPool()
	}

	tlsConfigServer.RootCAs.AddCert(ca)

	return tlsConfigServer, nil
}

func (c *GoproxyConfigServer) Cert(hostname string) (*tls.Config, error) {
	return c.cert(hostname)
}

func (c *GoproxyConfigServer) cert(hostname string) (*tls.Config, error) {
	return c.certWithCommonName(hostname, "")
}


func (c *GoproxyConfigServer) certWithCommonName(host string, commonName string) (*tls.Config, error) {

	fmt.Println("[DEBUG] certWithCommonName:", host)
	// Need a lock to protect the certificate store. Can't block here because we may already be writing a certificate.
	certmu.RLock()
	hostmetadata, found := c.Host[host]
	certmu.RUnlock()

	// In a race condition, it is possible that multiple threads could attempt to create a metadata entry. That's ok
	// because in the worst cast, we'll fetch the downstream certificate multiple times on the initial call.
	if !found {
		hostmetadata = &HostInfo{}
	} else {
		return (*hostmetadata).Config, nil
	}

	// Get a lock only on this domain name
	(*hostmetadata).mu.Lock()
	defer (*hostmetadata).mu.Unlock()

	// Begin downstream certificate retrieval and copy logic
	var origcert *x509.Certificate

	// Skip upstream lookup for local Winston... it doesn't exist in public DNS.
	// Also skip upstream checks if a previous attempt failed to validate.
	badcert := false
	var conn *tls.Conn

	conn, err := tls.Dial("tcp", host + ":443", &tls.Config{InsecureSkipVerify: true})

	if err != nil {
		fmt.Printf("[DEBUG] Signer.go - Error while dialing %s: %v\n", host, err)
		return nil, err
	} else {
		//fmt.Println("[DEBUG] Signer.go() DialWithDialer() completed", host)
		// Only close the connection if we couldn't connect.
		defer conn.Close()
		if len(conn.ConnectionState().PeerCertificates) >= 1 {
			origcert = conn.ConnectionState().PeerCertificates[0]
		} else {
			fmt.Printf("[ERROR] signer.go - no peer certificates. This shouldn't happen. %s\n", host)
		}
	}


	// Create a new certificate.
	serial, err := rand.Int(rand.Reader, MaxSerialNumber)
	if err != nil {
		return nil, err
	}

	certificateCommonName := host
	if len(commonName) > 0 {
		certificateCommonName = commonName
		//fmt.Printf("  *** Overrode common name with %s \n", commonName)
	}

	// Determine the validity period. This has to be set when the certificate is created.
	// If the intermediate certificate chain check failed, we need to invalidate the certificate and add it to the
	// store. This prevents us from retrieving it over and over again. If we just add the original certificate,
	// Golang is not smart enough to check the intermediate chains (and this would introduce an unacceptable performance
	// penalty if we did check it on every call anyway).
	var notbefore, notafter time.Time

	notafter = time.Now().Add(c.validity)
	notbefore = time.Now().Add(-c.validity)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   certificateCommonName,
			Organization: []string{OrganizationName},
		},
		SubjectKeyId:          c.keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth },
		BasicConstraintsValid: true,
		NotBefore:             notbefore,
		NotAfter:              notafter,
	}

	tmpl.DNSNames = []string{host}

	// If we have a non-Winston certificate for an external site, then copy values from the original certificate to our new one
	if origcert != nil {

		tmpl.Subject = origcert.Subject
		//tmpl.NotBefore = origcert.NotBefore
		//tmpl.NotAfter = origcert.NotAfter
		tmpl.KeyUsage = origcert.KeyUsage
		tmpl.AuthorityKeyId = origcert.AuthorityKeyId
		tmpl.IPAddresses = origcert.IPAddresses

		// If the DNS name points to winston.conf, then use the original hostname.
		if len(origcert.DNSNames) > 0 && origcert.DNSNames[0] != "winston.conf" {
			//fmt.Printf("  *** overwriting cert with original values: host=%s  DNSNames[0]=%s\n", originalhostname, origcert.DNSNames[0] )
			tmpl.DNSNames = origcert.DNSNames
		} else {
			//fmt.Printf("  *** Blocked domain.: host=%s  DNSNames[0]=%s\n", originalhostname, hostname )
			tmpl.DNSNames = []string{host}
		}
	}



	raw, err := x509.CreateCertificate(rand.Reader, tmpl, c.Root, c.priv.Public(), c.capriv)
	if err != nil {
		return nil, err
	}

	// Parse certificate bytes so that we have a leaf certificate.
	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}

	tlsc := &tls.Certificate{
		Certificate: [][]byte{raw, c.Root.Raw},
		PrivateKey:  c.priv,
		Leaf:        x509c,
	}

	// It's possible we have a race condition here with multiple goroutines having fetched the downstream certificate simultaneously.
	// The certificate verification logic avoids stampede conditions and will bypass validation logic if it detects multiple requests.
	// Therefore, we should check if a certificate already exists and only overwrite it if we determined it's invalid.
	certmu.Lock()
	defer certmu.Unlock()
	(*hostmetadata).LastVerify = time.Now()
	if !found || badcert {
		// Only add it if we didn't find it or ours is invalid

		// Create new config
		newtlsconfig := &tls.Config{
			//RootCAs: x509.NewCertPool(),
		}

		newtlsconfig.RootCAs = c.RootCAs
		newtlsconfig.Certificates = make([]tls.Certificate, 0)
		newtlsconfig.Certificates = append(newtlsconfig.Certificates, *tlsc)
		newtlsconfig.NameToCertificate = make(map[string]*tls.Certificate)
		newtlsconfig.NameToCertificate[host] = tlsc

		// Hook the certificate chain verification
		//if c.VerifyPeerCertificate != nil {
		//	newtlsconfig.VerifyPeerCertificate = c.VerifyPeerCertificate
		//}

		(*hostmetadata).Config = newtlsconfig

		c.Host[host] = hostmetadata
		return newtlsconfig, nil
	}

	return (*hostmetadata).Config, nil
}




func LoadDefaultConfig() error {
	config, err := LoadCAConfig("", CA_CERT, CA_KEY)
	if err != nil {
		return fmt.Errorf("Error parsing builtin CA: %s", err.Error())
	}
	TestCaConfig = config
	return err
}


// Load a CAConfig bundle from by arrays.  You can then load them into
// the proxy with `proxy.SetMITMCertConfig. If filename is non-nil, will attempt to load from disk.
func LoadCAConfig(filename string, caCert, caKey []byte) (*GoproxyConfigServer, error) {

	ca, err := tls.X509KeyPair(caCert, caKey)

	if err != nil {
		return nil, err
	}
	priv := ca.PrivateKey
	ca509, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, err
	}
	config, err := NewConfigServer(filename, ca509, priv)
	return config, err
}

func rootCAs(c *rootcerts.Config) *tls.Config {

	t := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS11,
		MaxVersion:         tls.VersionTLS12,
		Renegotiation:      tls.RenegotiateFreelyAsClient,
	}


	err := rootcerts.ConfigureTLS(t, c)
	if err != nil {
		fmt.Println("[Warning] Error loading root certs", err)
	}
	return t
}


var CA_CERT = []byte(`-----BEGIN CERTIFICATE-----
MIIChTCCAe6gAwIBAgIBADANBgkqhkiG9w0BAQsFADA2MQswCQYDVQQGEwJVUzEQ
MA4GA1UECgwHV2luc3RvbjEVMBMGA1UEAwwMd2luc3Rvbi5jb25mMB4XDTE4MDIy
MzE4NTExNVoXDTM4MDIxODE4NTExNVowNjELMAkGA1UEBhMCVVMxEDAOBgNVBAoM
B1dpbnN0b24xFTATBgNVBAMMDHdpbnN0b24uY29uZjCBnzANBgkqhkiG9w0BAQEF
AAOBjQAwgYkCgYEAu+LAQcFv/kIbgTPdmFmIcdFVvIONOiK6yWfjObQBwJOaRuZx
FgfojIFdRmm4SvOEhQp+/FZQQwHunDXy1ICNuEGveJyxxVh+FKfhKvwa7HcejZRe
z9BCun4vtSyOBMFkBn/oXKkK3zG7hZKsAjZiftO2m2CKTpR7mRVZHzoFDXMCAwEA
AaOBojCBnzAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVy
YXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUcDIKYDmsRzhFGibcyJ0tCX9OYZYw
HwYDVR0jBBgwFoAUV9oF/beeIssH3fAByRVyt8Mh+kIwFwYDVR0RBBAwDoIMd2lu
c3Rvbi5jb25mMAsGA1UdDwQEAwIFoDANBgkqhkiG9w0BAQsFAAOBgQCEhewUly9a
+LGp3HN0JagOk96cD13fmCTTzCtZH6jPXVoV1li2eQqI1UOxSqAnYD9D/KWqKkPg
zngMDIDjRXBIIMlGldKcPqC6/xKQxavGDZV4dvqRByKfPAJoam66nfN0vNaGS6dF
sCs4ajBfOFjOd62D1lpyKXFyW3dt2rxacg==
-----END CERTIFICATE-----`)

var CA_KEY = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC74sBBwW/+QhuBM92YWYhx0VW8g406IrrJZ+M5tAHAk5pG5nEW
B+iMgV1GabhK84SFCn78VlBDAe6cNfLUgI24Qa94nLHFWH4Up+Eq/Brsdx6NlF7P
0EK6fi+1LI4EwWQGf+hcqQrfMbuFkqwCNmJ+07abYIpOlHuZFVkfOgUNcwIDAQAB
AoGAYoxp+VOD8aItGRTiS1HS7pg1Vz7NKcwjmxahqZeQP7lr93pRoJOfV2tXSGKV
ZsLaJIo/1w1S5gKybD8j0nBnZHGnE+5eViuAwWLmHrcQo2Zx8Wsd1ooQce/UsL27
PjimImkLdLrCDPnavD2jrInZtWKfgP0QpaC1OyW3WHlR5OkCQQD0lnF5fbCPWpLy
qCKEQrPxVugf+sccEJ5u8Zww6MWIU8a5/299WsJL8WolnyM+xsZs7+bnx66PUjMR
FO30zDbFAkEAxKcDY2HNripMpg5uG23EGUcqvtjADnTxATrFl72OIpAHaxGsEowu
iJERWNbJnKr0p6Z0JyA/PX5yixpf5ne21wJBAJXaatHNwVRDYQ8NFoDEQW1XGscl
JcK7J+a/XzvUEdpxwasJpmw+JBbVZXyBYN3Aeaga3/UYMYocCa+ojBZU3CUCQGLd
ZEKuhO0uruI9FvYLNS9QLBlOdx/NguyPU4956N9PcatOcyfP+gUGiaYUNb/h4qX2
dSbGe4S68XMli1kejnkCQFNo6CZx31jiy57J5rjJZE6LM7OtSTBtSYJ3aE1ZUPnk
6fjNzFMU+APTWib1YsZQF/mrVh9q52CkA5Nnwpxfkjc=
-----END RSA PRIVATE KEY-----`)
