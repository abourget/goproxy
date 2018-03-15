/* Copyright (C) Winston Privacy, Inc - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Based on GoProxy. Modified by Richard Stokes <rich@winstonprivacy.com>, 2018
*/

/* Responsible for signing certificates based on Winston root certificate.
 * TODO: Check validity of certificates on first load rather than simply passing them on to clients.
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

// Config is a set of configuration values that are used to build TLS configs
// capable of MITM.
type GoproxyConfig struct {
	Root   *x509.Certificate
	capriv interface{}

	priv  *rsa.PrivateKey
	keyID []byte

	validity time.Duration

	certmu sync.RWMutex

	*tls.Config
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
	}
	if tlsConfig.Config.RootCAs == nil {
		tlsConfig.Config.RootCAs = x509.NewCertPool()
	}
	tlsConfig.Config.RootCAs.AddCert(ca)
	tlsConfig.Config.Certificates = make([]tls.Certificate, 0)
	tlsConfig.Config.NameToCertificate = make(map[string]*tls.Certificate)

	return tlsConfig, nil
}


func (c *GoproxyConfig) cert(hostname string) error {
	return c.certWithCommonName(hostname, "")
}

// RLS 7/14/2017
// If commonName is provided, it will be used in the certificate. This is used to
// service non-SNI requests.
func (c *GoproxyConfig) certWithCommonName(hostname string, commonName string) error {

	originalhostname := hostname

	/*experiment := false
	if strings.Contains(originalhostname, "badssl.com") || strings.Contains(originalhostname, "facebook.com") {
		fmt.Printf("  *** Starting badssl experiment: %s\n", originalhostname)
		experiment = true
	}*/

	// Remove the port if it exists.
	host, port, err := net.SplitHostPort(hostname)
	if err == nil {
		hostname = host
	}


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
		/*if experiment {
			fmt.Printf("  *** Cached cert used for %s.\n     Subject: %+v\n     DNS Names:%+v\n     IssuingCertificateURL: %+v\n     Issuer: %+v\n     Valid: %+v - %+v\n", hostname, tlsc.Leaf.Subject, tlsc.Leaf.DNSNames, tlsc.Leaf.IssuingCertificateURL, tlsc.Leaf.Issuer, tlsc.Leaf.NotBefore, tlsc.Leaf.NotAfter)
		}*/

		// Check validity of the certificate for hostname match, expiry, etc. In
		// particular, if the cached certificate has expired, create a new one.
		if _, err := tlsc.Leaf.Verify(x509.VerifyOptions{
			DNSName: hostname,
			Roots:   c.RootCAs,
		}); err == nil {
			return nil
		}
	}

	// Test: Get the origin certificate and copy fields to it.
	var origcert *x509.Certificate
	//if experiment {

		// Have to add the port number to connect. Assume 443.
		if port == "" {
			port = "443"
		}

		conn, err := tls.Dial("tcp", originalhostname + ":" + port, &tls.Config{InsecureSkipVerify: true})

		if err != nil {
			fmt.Printf("  *** Couldn't connect to destination [%s]\n", originalhostname)
		} else {
			// Only close the connection if we couldn't connect.
			defer conn.Close()
			if len(conn.ConnectionState().PeerCertificates) >= 1 {
				origcert = conn.ConnectionState().PeerCertificates[0]
				//fmt.Printf("  *** original cert: %s (%d)\n     Subject: %s\n     Issuer: %+v\n     DNS Names: %s\n     IssuingCertificateURL: %+v\n     Signature Algorithm: %+v\n", originalhostname, len(conn.ConnectionState().PeerCertificates), origcert.Subject, origcert.Issuer, origcert.DNSNames, origcert.IssuingCertificateURL, origcert.SignatureAlgorithm)
				fmt.Printf("  *** original cert: %s (%d)\n     Subject: %s\n     Issuer: %+v\n     DNS Names: %s\n", originalhostname, len(conn.ConnectionState().PeerCertificates), origcert.Subject, origcert.Issuer, origcert.DNSNames)

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
	//}

	// Create a new certificate
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

	// Experiment: copy values from the original certificate to our new one
	if origcert != nil {
		tmpl.Subject = origcert.Subject
		tmpl.NotBefore = origcert.NotBefore
		tmpl.NotAfter = origcert.NotAfter
		tmpl.DNSNames = origcert.DNSNames
		tmpl.IPAddresses = origcert.IPAddresses
		tmpl.KeyUsage = origcert.KeyUsage
		//tmpl.SubjectKeyId = origcert.SubjectKeyId
		tmpl.AuthorityKeyId = origcert.AuthorityKeyId
		//tmpl.CRLDistributionPoints = origcert.CRLDistributionPoints
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

	c.certmu.Lock()
	c.NameToCertificate[hostname] = tlsc
	c.Certificates = append(c.Certificates, *tlsc)
	c.certmu.Unlock()

	return nil
}
