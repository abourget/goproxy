/* Copyright (C) Winston Privacy, Inc - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Based on GoProxy. Modified by Richard Stokes <rich@winstonprivacy.com>, 2018
*/

/* Responsible for signing certificates based on Winston root certificate.
 * TODO: Check validity of certificates on first load rather than simply passing them on blindly to clients.
 */
package goproxy

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
	"strings"
	"sync"
	"time"
	"fmt"
	"github.com/benburkert/dns"
	"github.com/nathanejohnson/intransport"
	"encoding/gob"
	"io/ioutil"
	"os"
	//"runtime/debug"
)

// OrganizationName is the name your CA cert will be signed with. It
// will show in your different UIs. Change it globally here to show
// meaningful things to your users.
var OrganizationName = "Winston Privacy, Inc."

// MaxSerialNumber is the upper boundary that is used to create unique serial
// numbers for the certificate. This can be any unsigned integer up to 20
// bytes (2^(8*20)-1).
var MaxSerialNumber = big.NewInt(0).SetBytes(bytes.Repeat([]byte{255}, 20))

func getWildcardHost(host string) string {
	first := strings.Index(host, ".")
	if first <= 0 {
		return host
	}
	last := strings.LastIndex(host, ".")
	if last == first {
		// root domain, no wildcard
		return host
	}
	return "*" + host[first:]
}

// Used to resolve certificate chains (Global)
var certtransport	*intransport.InTransport

// Global lock on the certificate store. Locks cannot be copied so they were removed from GoproxyConfig.
var certmu          	sync.RWMutex

// Stores metadata about a particular host. Used to improve performance.
type HostInfo struct {
	LastVerify 	time.Time
	mu 		sync.Mutex
}

// Config is a set of configuration values that are used to build TLS configs
// capable of MITM.
type GoproxyConfig struct {
	Root            *x509.Certificate
	capriv          interface{}
	priv            *rsa.PrivateKey
	keyID           []byte
	validity        time.Duration
	*tls.Config
	bypassDnsDialer *net.Dialer // Custom DNS resolver
	Host		map[string]*HostInfo
}

// NewConfig creates a MITM config using the CA certificate and
// private key to generate on-the-fly certificates.
func NewConfig(filename string, ca *x509.Certificate, privateKey interface{}) (*GoproxyConfig, error) {
	needcert := true
	var priv *rsa.PrivateKey
	var err error

	if filename != "" {
		_, err := os.Stat(filename)

		if !os.IsNotExist(err) {
			// File exists. Read it.
			buf, err := ioutil.ReadFile(filename)
			if err == nil {
				config := rsa.PrivateKey{}
				dec := gob.NewDecoder(bytes.NewReader(buf))
				err = dec.Decode(&config)
				if err == nil {
					// Found an existing certificate
					fmt.Println("[INFO] Using cached private key")
					priv = &config
					needcert = false
				}
			}
		}
	}


	if needcert {
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	}

	// Save the key to disk
	if filename != "" && err == nil {
		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)
		err = enc.Encode(priv)
		if err == nil {
			err = ioutil.WriteFile(filename, buff.Bytes(), 0644)
		} else {
			fmt.Printf("[ERROR] Couldn't persist private key to disk %+v\n", err)
		}
	}


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

	tlsConfig := &GoproxyConfig{
		Root:     ca,
		capriv:   privateKey,
		priv:     priv,
		keyID:    keyID,
		validity: time.Hour * 24 * 3650,
		Config:   rootCAs(nil),
		bypassDnsDialer:	  WhitelistedDNSDialer(),

	}
	if tlsConfig.Config.RootCAs == nil {
		tlsConfig.Config.RootCAs = x509.NewCertPool()
	}
	tlsConfig.Config.RootCAs.AddCert(ca)
	tlsConfig.Config.Certificates = make([]tls.Certificate, 0)
	tlsConfig.Config.NameToCertificate = make(map[string]*tls.Certificate)

	// Used to check certificate chains when we create new MITM certs
	//tlsConfig.Config / nil
	certtransport = intransport.NewInTransport(nil)

	//tlsConfig.Config.VerifyPeerCertificate = tlsConfig.VerifyPeerCertificate

	tlsConfig.Host = make(map[string]*HostInfo)

	return tlsConfig, nil
}

// Returns a DNS dialer for port 54 (whitelisted DNS)
// TODO: Should we check for DNS server on port 54 and default to port 53 if not available? For now, caller is responsible for this.
func WhitelistedDNSDialer() (*net.Dialer) {
	dnsclient := new(dns.Client)

	proxy := dns.NameServers{
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54},
	}.First()

	dnsclient.Transport = &dns.Transport{
		Proxy: proxy,
	}

	// This is a http/s dialer with a custom DNS resolver.
	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: dnsclient.Dial,
		},
	}

	return dialer
}

// RLS 3/19/2018 - exported for testng
func (c *GoproxyConfig) Cert(hostname string) error {
	return c.cert(hostname)
}

func (c *GoproxyConfig) cert(hostname string) error {
	return c.certWithCommonName(hostname, "")
}

// Removes the certificate associated with the given hostname from the cache. This is necessary if we change the
// whitelist or blacklist settings for a domain.
func (c *GoproxyConfig) FlushCert(hostname string) {
	// Remove the port if it exists.
	host, _, err := net.SplitHostPort(hostname)
	if err == nil {
		hostname = host
	}
	certmu.Lock()
	defer certmu.Unlock()
	delete(c.NameToCertificate, hostname)
}

// If commonName is provided, it will be used in the certificate. This is used to
// service non-SNI requests.
// TODO: commonName may no longer be needed. Refactor to remove it.
// TODO: Should we remember bad requests so we don't keep making them? Routine is subject to an internal flood attack.
func (c *GoproxyConfig) certWithCommonName(hostname string, commonName string) error {

	//experiment := false
	//if strings.Contains(hostname, "winston.conf") {
	//	//fmt.Printf("  *** Starting badssl experiment: %s\n", originalhostname)
	//	experiment = true
	//}
	// Remove the port if it exists.
	// host must contain a domain/IP address only at this point.
	host, port, err := net.SplitHostPort(hostname)
	if err == nil {
		hostname = host
	} else {
		host = hostname
	}

	// Is this an IP address?
	isIP := false
	ip := net.ParseIP(host);
	if ip != nil {
		isIP = true
	}

	// Here we employ a lock to protect the certificate store and metadata map and then another lock to
	// protect individual hosts. This is intended to prevent simultaneous requests from retrieving downstream
	// certificates at the same time but reduce contention for the certificate store when different domains are
	// requested.
	certmu.Lock()

	// Get the certificate from the local cache
	hostmetadata, found := c.Host[host]
	if !found {
		// Create a HostInfo struct because we'll need the lock.
		hostmetadata = &HostInfo{}
		c.Host[host] = hostmetadata
	}
	(*hostmetadata).mu.Lock()
	defer (*hostmetadata).mu.Unlock()

	tlsc, ok := c.NameToCertificate[host]
	certmu.Unlock()

	// A write lock on the host record is held at this point

	if ok {
		//if experiment {
		//	//fmt.Printf("  *** Cached cert used for %s.\n     Subject: %+v\n     DNS Names:%+v\n     IssuingCertificateURL: %+v\n     Issuer: %+v\n     Valid: %+v - %+v\n", hostname, tlsc.Leaf.Subject, tlsc.Leaf.DNSNames, tlsc.Leaf.IssuingCertificateURL, tlsc.Leaf.Issuer, tlsc.Leaf.NotBefore, tlsc.Leaf.NotAfter)
		//	fmt.Printf("[DEBUG] certWithCommonName - Cached cert used. Subject: %+v\n  Issuer: %+v\n  AuthorityKeyId=%v\n", tlsc.Leaf.Subject.CommonName, tlsc.Leaf.Issuer.CommonName, tlsc.Leaf.AuthorityKeyId)
		//}

		// Check validity of the certificate for hostname match, expiry, etc. In
		// particular, if the cached certificate has expired, create a new one.
		// Don't check more than once an hour.
		if hostmetadata.LastVerify.Before(time.Now().Add(-60 * time.Minute)) {
			fmt.Printf("[DEBUG] Verifying certificate [%s]\n", host)
			var err error
			if isIP {
				// Don't verify hostname if we have an ip address
				// Special case: if localhost, don't bother verifying. This makes unit testing much easier.
				if !strings.HasPrefix(host, "127.0.0.") {
					_, err = tlsc.Leaf.Verify(x509.VerifyOptions{
						//DNSName: hostname,
						Roots:   c.RootCAs,
					})
				}
			} else {
				_, err = tlsc.Leaf.Verify(x509.VerifyOptions{
					DNSName: host,
					Roots:   c.RootCAs,
				})
			}
			if err == nil {
				// Update the last verification time
				(*hostmetadata).LastVerify = time.Now()
				return nil
			}
		} else {
			//fmt.Printf("[DEBUG] Skipping certificate verify [%s]\n", host)
			return nil
		}
	}

	//if experiment {
	//	fmt.Println("[DEBUG] Signer.go - about to generate new certificate.")
	//}

	// Test: Get the origin certificate and copy fields to it.
	var origcert *x509.Certificate

	// Have to add the port number to connect. Assume 443.
	if port == "" {
		port = "443"
	}

	// Skip upstream lookup for local Winston... it doesn't exist in public DNS.
	if !strings.Contains(hostname, "winston.conf") {

		//if experiment {
		//	fmt.Println("[DEBUG] Signer.go - about to dial")
		//}

		var conn *tls.Conn
		// TODO: This breaks the original goproxy unit tests.


		fmt.Println("[DEBUG] Signer.go() Downloading remote certificate", host)
		conn, err = tls.DialWithDialer(c.bypassDnsDialer, "tcp", host + ":" + port, &tls.Config{InsecureSkipVerify: true})

		//if experiment {
		//	fmt.Println("[DEBUG] Signer.go - dialed - err:", err)
		//}

		if err != nil {
			//fmt.Printf("[DEBUG] Signer.go - Error while dialing: %v\n", err)
			return err
		} else {
			// Only close the connection if we couldn't connect.
			defer conn.Close()
			if len(conn.ConnectionState().PeerCertificates) >= 1 {
				origcert = conn.ConnectionState().PeerCertificates[0]

				// TODO: Throttle this so we don't make a ton of requests all at once

				//var rawCerts [][]byte
				rawCerts := make([][]byte, len(conn.ConnectionState().PeerCertificates))
				for i, cert := range conn.ConnectionState().PeerCertificates {
					rawCerts[i] = cert.Raw
				}

				err = certtransport.VerifyPeerCertificate(rawCerts, nil)
				if err != nil {
					//fmt.Printf("[DEBUG] certWithCommonName() - Couldn't verify certificate chain.\n")
					return nil
				}

				//fmt.Printf("[DEBUG] certWithCommonName() - successfully verified certificate chain.\n")

				// TODO: Check upstream server's certificate and deny if it is encoded in SHA-1
				// https://ssldecoder.org/?host=sha1-intermediate.badssl.com&port=&csr=&s=
			}
		}
	}

	// Create a new certificate.
	//certmu.Lock()
	//defer certmu.Unlock()

	serial, err := rand.Int(rand.Reader, MaxSerialNumber)
	if err != nil {
		return err
	}

	certificateCommonName := host
	if len(commonName) > 0 {
		certificateCommonName = commonName
		//fmt.Printf("  *** Overrode common name with %s \n", commonName)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   certificateCommonName,
			Organization: []string{OrganizationName},
		},
		SubjectKeyId:          c.keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-c.validity),
		NotAfter:              time.Now().Add(c.validity),
	}

	if isIP {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	// If we have a non-Winston certificate for an external site, then copy values from the original certificate to our new one
	if origcert != nil && !strings.HasPrefix(host, "winston.conf") {

		tmpl.Subject = origcert.Subject
		tmpl.NotBefore = origcert.NotBefore
		tmpl.NotAfter = origcert.NotAfter
		tmpl.KeyUsage = origcert.KeyUsage

		// TODO: Are we copying the original Authority Key Id
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
		return err
	}

	// Parse certificate bytes so that we have a leaf certificate.
	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return err
	}

	tlsc = &tls.Certificate{
		Certificate: [][]byte{raw, c.Root.Raw},
		PrivateKey:  c.priv,
		Leaf:        x509c,
	}

	//if experiment {
	//	fmt.Printf("[DEBUG] certWithCommonName - New cert created. Subject: %+v\n  Issuer: %+v\n  AuthorityKeyId=%v\n", tlsc.Leaf.Subject.CommonName, tlsc.Leaf.Issuer.CommonName, tlsc.Leaf.AuthorityKeyId)
	//}

	// We don't need to lock the certificate store because we already have a lock on this hostname.
	c.NameToCertificate[host] = tlsc
	c.Certificates = append(c.Certificates, *tlsc)

	// Update the last verification time.
	(*hostmetadata).LastVerify = time.Now()
	c.Host[host] = hostmetadata


	return nil
}

// Used for unit testing. Gets a certificate from a server and port and creates a local version suitable for MITM.
func (c *GoproxyConfig) GetTestCertificate(host string, port string) error {


	// Is this an IP address?
	isIP := false
	ip := net.ParseIP(host);
	if ip != nil {
		isIP = true
	}

	// Test: Get the origin certificate and copy fields to it.
	var origcert *x509.Certificate
	//if experiment {

	// Have to add the port number to connect. Assume 443.
	if port == "" {
		port = "443"
	}

	var conn *tls.Conn
	var err error

	conn, err = tls.Dial("tcp", host + ":" + port, &tls.Config{InsecureSkipVerify: true})

	if err != nil {
		fmt.Printf("[DEBUG] GetTestCertificate - Error while dialing: %v\n", err)
		return err
	} else {
		// Only close the connection if we couldn't connect.
		defer conn.Close()
	}

	// Create a new certificate
	certmu.Lock()
	defer certmu.Unlock()

	serial, err := rand.Int(rand.Reader, MaxSerialNumber)
	if err != nil {
		return err
	}

	certificateCommonName := host
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   certificateCommonName,
			Organization: []string{OrganizationName},
		},
		SubjectKeyId:          c.keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-c.validity),
		NotAfter:              time.Now().Add(c.validity),
	}

	if isIP {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	// If we have a non-Winston certificate for an external site, then copy values from the original certificate to our new one
	if origcert != nil && !strings.HasPrefix(host, "winston.conf") {

		tmpl.Subject = origcert.Subject
		tmpl.NotBefore = origcert.NotBefore
		tmpl.NotAfter = origcert.NotAfter
		tmpl.KeyUsage = origcert.KeyUsage

		// TODO: Are we copying the original Authority Key Id
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
		return err
	}

	// Parse certificate bytes so that we have a leaf certificate.

	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return err
	}

	tlsc, _ := c.NameToCertificate[host]

	tlsc = &tls.Certificate{
		Certificate: [][]byte{raw, c.Root.Raw},
		PrivateKey:  c.priv,
		Leaf:        x509c,
	}

	c.NameToCertificate[host] = tlsc
	c.Certificates = append(c.Certificates, *tlsc)

	return nil
}

