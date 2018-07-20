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


// Config is a set of configuration values that are used to build TLS configs
// capable of MITM.
type GoproxyConfig struct {
	Root            *x509.Certificate
	capriv          interface{}
	priv            *rsa.PrivateKey
	keyID           []byte
	validity        time.Duration
	certmu          sync.RWMutex
	*tls.Config
	bypassDnsDialer *net.Dialer // Custom DNS resolver
}

// NewConfig creates a MITM config using the CA certificate and
// private key to generate on-the-fly certificates.
func NewConfig(ca *x509.Certificate, privateKey interface{}) (*GoproxyConfig, error) {

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
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

	return tlsConfig, nil
}

// Returns a DNS dialer for port 54 (whitelisted DNS)
// TODO: Should we check for DNS server on port 54 and default to port 53 if not available? For now, caller is responsible for this.
func WhitelistedDNSDialer() (*net.Dialer) {
	dnsclient := new(dns.Client)

	proxy := dns.NameServers{
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54},
	}.Upstream(rand.Reader)

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
	fmt.Printf("[DEBUG] FlushCert(%s)\n", hostname)

	_, ok := c.NameToCertificate[hostname]
	if !ok {
		fmt.Println("[DEBUG] Didn't find existing certificate")
	}

	// Remove the port if it exists.
	host, _, err := net.SplitHostPort(hostname)
	if err == nil {
		hostname = host
	}
	delete(c.NameToCertificate, hostname)

	_, ok = c.NameToCertificate[hostname]
	if !ok {
		fmt.Println("[DEBUG] The certificate has been deleted")
	}
}

// If commonName is provided, it will be used in the certificate. This is used to
// service non-SNI requests.
// TODO: commonName may no longer be needed. Refactor to remove it.
// TODO: Should we remember bad requests so we don't keep making them? Routine is subject to an internal flood attack.
func (c *GoproxyConfig) certWithCommonName(hostname string, commonName string) error {

	originalhostname := hostname

	//experiment := false
	//if strings.Contains(originalhostname, "xaxis") {
	//	//fmt.Printf("  *** Starting badssl experiment: %s\n", originalhostname)
	//	experiment = true
	//}
	// Remove the port if it exists.
	host, port, err := net.SplitHostPort(hostname)
	if err == nil {
		hostname = host
	}

	//fmt.Printf("[DEBUG] certWithCommonName(%s)\n", hostname)

	// Is this an IP address?
	isIP := false
	ip := net.ParseIP(hostname);
	if ip != nil {
		isIP = true
	}

	// Convert to a wildcard host (*.example.com)
	// Keep our hostname for the experiment
	/*
	if !experiment && !isIP {
		hostname = getWildcardHost(hostname)
	}
	*/

	// Get the certificate from the local cache
	c.certmu.RLock()
	tlsc, ok := c.NameToCertificate[hostname]
	c.certmu.RUnlock()


	if ok {
		//if experiment {
		//	//fmt.Printf("  *** Cached cert used for %s.\n     Subject: %+v\n     DNS Names:%+v\n     IssuingCertificateURL: %+v\n     Issuer: %+v\n     Valid: %+v - %+v\n", hostname, tlsc.Leaf.Subject, tlsc.Leaf.DNSNames, tlsc.Leaf.IssuingCertificateURL, tlsc.Leaf.Issuer, tlsc.Leaf.NotBefore, tlsc.Leaf.NotAfter)
		//	fmt.Printf("[DEBUG] certWithCommonName - Cached cert used. Subject: %+v\n  Issuer: %+v\n  AuthorityKeyId=%v\n", tlsc.Leaf.Subject.CommonName, tlsc.Leaf.Issuer.CommonName, tlsc.Leaf.AuthorityKeyId)
		//}

		// Check validity of the certificate for hostname match, expiry, etc. In
		// particular, if the cached certificate has expired, create a new one.
		var err error
		if isIP {
			// Don't verify hostname if we have an ip address

			_, err = tlsc.Leaf.Verify(x509.VerifyOptions{
				//DNSName: hostname,
				Roots:   c.RootCAs,
			})
		} else {
			_, err = tlsc.Leaf.Verify(x509.VerifyOptions{
				DNSName: hostname,
				Roots:   c.RootCAs,
			})
		}
		if err == nil {
			//if experiment {
			//	fmt.Printf("[DEBUG] certWithCommonName() - Certificate passes expiration and hostname check. Using it.\n")
			//}
			return nil
		}

		//if experiment {
		//	fmt.Printf("[DEBUG] certWithCommonName() - Certificate did not verify. Getting a new one.\n")
		//}
	}

	// Test: Get the origin certificate and copy fields to it.
	var origcert *x509.Certificate
	//if experiment {

	// Have to add the port number to connect. Assume 443.
	if port == "" {
		port = "443"
	}

	var conn *tls.Conn

	conn, err = tls.DialWithDialer(c.bypassDnsDialer, "tcp", originalhostname + ":" + port, &tls.Config{InsecureSkipVerify: true})






	if err != nil {
		return err
	} else {
		// Only close the connection if we couldn't connect.
		defer conn.Close()
		if len(conn.ConnectionState().PeerCertificates) >= 1 {
			origcert = conn.ConnectionState().PeerCertificates[0]

			// TODO: Verify the original certificate
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

			// Todo: Check the validity of the certificate. We need to figure out how to
			// query the installed trusted roots of the operating system. This is needed
			// to block SHA-1 certificates. For now, the browser will be responsible for this.
			/*root, _ := x509.SystemCertPool()
			if _, err := origcert.Verify(x509.VerifyOptions{
				DNSName: hostname,
				Roots: root,	// Commented out to use default roots of the operating system
			}); err == nil {
				fmt.Printf("  *** The original certificate was valid.\n")
				//return nil
			} else {
				fmt.Printf("  *** The original certificate was invalid. Err: %+v\n", err)
			}*/
			// Check upstream server's certificate and deny if it is encoded in SHA-1
			// https://ssldecoder.org/?host=sha1-intermediate.badssl.com&port=&csr=&s=

		}
	}




	// Create a new certificate
	c.certmu.Lock()
	defer c.certmu.Unlock()

	serial, err := rand.Int(rand.Reader, MaxSerialNumber)
	if err != nil {
		return err
	}

	certificateCommonName := hostname
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
		tmpl.DNSNames = []string{hostname}
	}

	// If we have a non-Winston certificate for an external site, then copy values from the original certificate to our new one
	if origcert != nil && !strings.HasPrefix(originalhostname, "winston.conf") {

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
			tmpl.DNSNames = []string{hostname}
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
	//	//fmt.Printf("  *** New cert created for %s.\n     Subject: %+v\n     DNS Names:%+v\n     IssuingCertificateURL: %+v\n     Issuer: %+v\n     Valid: %+v - %+v\n", hostname, tlsc.Leaf.Subject, tlsc.Leaf.DNSNames, tlsc.Leaf.IssuingCertificateURL, tlsc.Leaf.Issuer, tlsc.Leaf.NotBefore, tlsc.Leaf.NotAfter)
	//	fmt.Printf("[DEBUG] certWithCommonName - New cert created. Subject: %+v\n  Issuer: %+v\n  AuthorityKeyId=%v\n", tlsc.Leaf.Subject.CommonName, tlsc.Leaf.Issuer.CommonName, tlsc.Leaf.AuthorityKeyId)
	//}
	// Todo: Should this be moved higher so we don't repeatedly request the same certificate from downstream server?
	// The risk is that a hung connection could block all HTTPS traffic to the proxy. Leaving it for now. RLS 3/16/2018

	c.NameToCertificate[hostname] = tlsc
	c.Certificates = append(c.Certificates, *tlsc)


	return nil
}

