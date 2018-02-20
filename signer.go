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
var OrganizationName = "GoProxy untrusted MITM proxy Inc"

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

	// Debug - this should never happen.
	if hostname == "" {
		fmt.Println("  *** NO HOST DETECTED IN CERT() ***")
	}

	// Remove the port if it exists.
	host, _, err := net.SplitHostPort(hostname)
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
	if !isIP {
		hostname = getWildcardHost(hostname)
	}

	// Remove the port if it exists.
	c.certmu.RLock()
	tlsc, ok := c.NameToCertificate[hostname]
	c.certmu.RUnlock()

	if ok {
		// Check validity of the certificate for hostname match, expiry, etc. In
		// particular, if the cached certificate has expired, create a new one.
		if _, err := tlsc.Leaf.Verify(x509.VerifyOptions{
			DNSName: hostname,
			Roots:   c.RootCAs,
		}); err == nil {
			return nil
		}
	}

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
