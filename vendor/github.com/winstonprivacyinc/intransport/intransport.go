package intransport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"golang.org/x/crypto/ocsp"
)

type certCacheEntry struct {
	sync.RWMutex
	cert *x509.Certificate
}

// TODO - consider replacing this with google group cache
type certCache struct {
	sync.Mutex
	m map[string]*certCacheEntry
	c *http.Client
}

// TODO - look into status_request_v2
const statusRequestExtension = 5

var (
	// MustStapleValue is the value in the MustStaple extension.
	// DER encoding of the status_request extension, 5.
	// https://tools.ietf.org/html/rfc6066#section-1.1
	MustStapleValue = []byte{0x30, 0x03, 0x02, 0x01, 0x05}

	// MustStapleOID is the OID of the must staple.
	//
	// Must staple oid is id-pe-tlsfeature  as defined here
	// https://tools.ietf.org/html/rfc7633#section-6
	MustStapleOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

	cc = &certCache{
		m: make(map[string]*certCacheEntry),
		// client used for fetching intermediates.
		c: &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   3 * time.Second,
					KeepAlive: 0,
					DualStack: true,
				}).DialContext,

				// Since we cache responses, all http activity should be
				// one-and-done.
				DisableKeepAlives: true,

				// This shouldn't be needed, since I don't believe
				// the server url locations are ever TLS enabled?
				TLSHandshakeTimeout: 3 * time.Second,

				// This also shouldn't be needed, but doesn't hurt anything
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
	}
)

// PeerCertVerifier - this is a method type that is plugged into a tls.Config.VerifyPeerCertificate,
// or into our NextVerifyPeerCertificate.
type PeerCertVerifier func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

// NewInTransportHTTPClient - generate an http client with sensible defaults.
// Optionally pass a *tls.Config that will be used as a basis for tls configuration.
func NewInTransportHTTPClient(tlsc *tls.Config) *http.Client {
	return &http.Client{
		Transport: NewInTransport(tlsc),
	}
}

// NewInTransport - create a new http transport suitable for client connections.
// InTransport implements http.RoundTripper, and can be used like so:
//
//    it := intransport.NewInTranport(nil)
//    c := &http.Client{
//        Transport: it,
//    }
func NewInTransport(tlsc *tls.Config) *InTransport {
	t := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		TLSClientConfig: tlsc,
	}
	return NewInTransportFromHTTPTransport(t)
}

// NewInTransportFromHTTPTransport - this allows you to pass in an http.Transport
// with pre-configured timeouts.  This is useful where you want to customize.
// Note that the transport passed in will be modified by this call.  Do not pass
// in a transport that's already in-use.  Will panic on a nil transport passed.
// if the passed transport has a TLSClientConfiguration defined, it will be
// cloned and then modified to integrate InTransport.  The following settings
// within TLSClientConnection will be modified:
//
// * InsecureSkipVerify will be set to true
//
// * VerifyPeerCertificate will be set to our InTransport.VerifyPeerCertificate
//
// As noted elsewhere, InsecureSkipVerify must be set in order for our
// VerifyPeerCertificate method to get called in the case of missing
// intermediates.  We still do the full certificate checking here, we just
// go about it a different way.
//
//     it := intransport.NewInTransportFromHTTPTransport(&http.Transport{
//         Proxy:                 http.ProxyFromEnvironment,
//         MaxIdleConns:          100,
//         IdleConnTimeout:       90 * time.Second,
//         ExpectContinueTimeout: 1 * time.Second,
//         TLSHandshakeTimeout:   10 * time.Second,
//         DialContext: (&net.Dialer{
//             Timeout:   30 * time.Second,
//             KeepAlive: 30 * time.Second,
//             DualStack: true,
//         }).DialContext,
//     }
//     c := &http.Client{
//         Transport: it,
//     }
func NewInTransportFromHTTPTransport(transport *http.Transport) *InTransport {
	it := &InTransport{
		Transport: transport,
	}

	if transport.TLSClientConfig != nil {
		it.TLS = transport.TLSClientConfig.Clone()
	} else {
		it.TLS = new(tls.Config)
	}
	it.TLS.VerifyPeerCertificate = it.VerifyPeerCertificate
	it.TLS.InsecureSkipVerify = true
	transport.TLSClientConfig = it.TLS
	return it
}

// InTransport - this implements an http.RoundTripper and handles the fetching
// of missing intermediate certificates, and verifying OCSP stapling, and
// in the event there is a "must staple" set on the certificate it will fail on
// missing staple.
type InTransport struct {
	// Specify this method in the situation where you might otherwise have wanted to
	// install your own VerifyPeerCertificate hook into tls.Config.  If specified,
	// This method will be called after a successful InTransport verification,
	// and verifiedChains will contain appropriate data including any intermediates
	// that needed to be downloaded.
	NextVerifyPeerCertificate PeerCertVerifier

	TLS                 *tls.Config
	TLSHandshakeTimeout time.Duration

	Transport *http.Transport
}

// RoundTrip - this implements the http.RoundTripper interface, and makes it suitable
// for use as a transport.
func (it *InTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := it.Transport.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	// Now verify hostname on TLS since we couldn't see it in our
	// VerifyPeerCertificate callback.
	if resp.TLS != nil {
		err := validateHost(resp.TLS.PeerCertificates, resp.Request.URL.Host)
		if err == nil {
			err = it.validateOCSP(resp.TLS)
		}

		if err != nil {
			// Closing the body without reading from it should signal closing the
			// underlying net.Conn in the case of keepalives enabled, which we
			// have on by default.
			_ = resp.Body.Close()
			return nil, err
		}

	} else if resp.Request.URL.Scheme == "https" {
		err := fmt.Errorf("https requested, but tls is nil")
		_ = resp.Body.Close()
		return nil, err
	}

	return resp, nil

}

// SetNextVerifyPeerCertificate - this is a setter method to specify a method
// to be called after a successful InTransport TLS validation.
// Specify this method in the situation where you might otherwise have wanted to
// install your own VerifyPeerCertificate hook into tls.Config.  verifiedChains will
// contain appropriate data including any intermediates that needed to be downloaded.
func (it *InTransport) SetNextVerifyPeerCertificate(verifier PeerCertVerifier) {
	it.NextVerifyPeerCertificate = verifier
}

func validateHost(certs []*x509.Certificate, host string) error {
	crt := certs[0]

	if hasPort(host) {
		host = host[:strings.LastIndex(host, ":")]
	}

	return crt.VerifyHostname(host)

}

func (it *InTransport) validateOCSP(connState *tls.ConnectionState) error {
	peers := connState.PeerCertificates
	if len(peers) == 0 {
		return fmt.Errorf("no peer certificates presented")
	}
	crt := peers[0]

	mustStaple := false
	for _, ext := range crt.Extensions {
		if ext.Id.Equal(MustStapleOID) {
			if bytes.Equal(ext.Value, MustStapleValue) {
				mustStaple = true
			} else {
				// technically the value is a DER encoded SEQUENCE OF INTEGER,
				// so see if there is more than one integer specified.  doubt
				// this will be seen in the wild.
				var tlsExts []int
				_, err := asn1.Unmarshal(ext.Value, &tlsExts)
				if err != nil {
					return fmt.Errorf("malformed must staple extension: %s", err)
				}
				for _, tlsExt := range tlsExts {
					if tlsExt == statusRequestExtension {
						mustStaple = true
						break
					}
				}
			}
			break
		}
	}

	validatedStaple := false

	if connState.OCSPResponse != nil {

		// Validate the staple if present
		// Let's grab the chain

		chains, err := it.verifyChains(peers)
		if err != nil {
			return err
		}

		var chain []*x509.Certificate
		if len(chains) < 1 {
			err = fmt.Errorf("invalid chains length")
		} else {
			chain = chains[0]
			if len(chain) < 2 {
				err = fmt.Errorf("invalid chain length")
			}
		}
		if err != nil {
			return err
		}

		ocspResp, err := ocsp.ParseResponseForCert(connState.OCSPResponse, crt, chain[1])
		if err != nil {
			return err
		}
		if ocspResp.Status != ocsp.Good {

			return fmt.Errorf("invalid ocsp validation: %s", ocsp.ResponseStatus(ocspResp.Status).String())
		}

		if !ocspResp.NextUpdate.Before(time.Now()) {
			// for now, don't fail on an expired staple unless must staple is specified.
			// maybe revisit this
			validatedStaple = true
		}

	}

	if mustStaple && !validatedStaple {
		return fmt.Errorf("certificate was marked with OCSP must-staple and no staple could be verified")
	}
	return nil
}

// lifted from standard library net/http/http.go
func hasPort(s string) bool { return strings.LastIndex(s, ":") > strings.LastIndex(s, "]") }

// VerifyPeerCertificate - this is the method that is to be plugged into
// tls.Config VerifyPeerCertificate.  If using this method inside of a custom
// built htttp.Transport, you must also set InsecureSkipVerify to true.  When
// set to false, a certificate that isn't trusted to the root and has missing
// intermediate certs will prevent VerifyPeerCertificate from being called.
// This method will still ensure that a valid chain exists from the presented
// certificates(s) to a trusted root certificate.  The difference between this
// and the default TLS verification is that missing intermediates will be
// fetched until either a valid path to a trusted root is found or no further
// intermediates can be found.  If a chain cannot be established, the
// connection will fail .  If a chain can be established, then the optional
// NextVerifyPeerCertificate() method will be called, if specified.  If this
// method returns an error, it will stop the connection.
func (it *InTransport) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {

	if len(rawCerts) == 0 {
		return fmt.Errorf("no certificates supplied")
	}

	// RLS FIX 7/20/2018
	// If multiple certificates are received, the self-signed ones should be ignored.
	ignoreSelfSignedCert := false
	if len(rawCerts) > 1 {
		ignoreSelfSignedCert = true
	}
	PeerCertificates := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return err
		}

		// Ignore self-signed/root certs

		if ignoreSelfSignedCert && cert.Subject.CommonName == cert.Issuer.CommonName {
			//fmt.Printf("Ignoring self-signed cert: %s\n", cert.Subject.CommonName)
		} else {
			PeerCertificates = append(PeerCertificates, cert)
			//fmt.Printf("VerifyPeerCertificates loop() - Subject: [%+v]\nDNS Names:%+v\nIssuer: [%+v]\n\n\n", cert.Subject.CommonName, cert.DNSNames, cert.Issuer.CommonName)
		}
	}

	// Only a self-signed certificate was sent. Return an error.
	// it: https://self-signed.badssl.com
	if len(PeerCertificates) == 0 {
		return fmt.Errorf("Certificate chain was sent with self-signed root.")
	}

	var err error
	var verifiedChains [][]*x509.Certificate
	verifiedChains, err = it.verifyChains(PeerCertificates)
	if err != nil {
		return err
	}
	if it.NextVerifyPeerCertificate != nil {
		err = it.NextVerifyPeerCertificate(rawCerts, verifiedChains)
	}

	return err
}

// verifyChains - this takes cert(s) and does it's best to find a path to a recognized root,
// fetching intermediate certs that may be missing.
func (it *InTransport) verifyChains(certs []*x509.Certificate) (chains [][]*x509.Certificate, err error) {

	//fmt.Printf("[DEBUG] verifyChains()...\n")
	cp := x509.NewCertPool()
	if len(certs) > 1 {
		for _, cert := range certs[1:] {
			//fmt.Printf("verifyChain() loop - cert/CN: %+v\n", cert.Subject.CommonName)
			if cert.SignatureAlgorithm != x509.SHA1WithRSA {
				cp.AddCert(cert)
			} //else {
			//	fmt.Printf("[DEBUG] Blocked SHA-1 intermediate cert 1\n")
			//}
		}
	}

	chains, err = certs[0].Verify(x509.VerifyOptions{
		Roots:         it.TLS.RootCAs,
		Intermediates: cp,
	})

	if err != nil {

		var dledIntermediates []*x509.Certificate

		dledIntermediates, err = it.buildChain(certs[len(certs)-1])
		if err != nil {
			return nil, fmt.Errorf("failed to find chain: %s", err)
		}
		for _, cert := range dledIntermediates {
			// TEST: Block SHA-1 certs
			if cert.SignatureAlgorithm != x509.SHA1WithRSA {
				//fmt.Printf("[DEBUG] Allowed intermediate cert\n")
				cp.AddCert(cert)
			} //else {
			//	fmt.Printf("[DEBUG] Blocked SHA-1 intermediate cert\n")
			//}
		}
		chains, err = certs[0].Verify(x509.VerifyOptions{
			Roots:         it.TLS.RootCAs,
			Intermediates: cp,
		})
		if err != nil {
			return nil, fmt.Errorf("chain failed verification after fetch: %s", err)
		}
	}
	return
}

func (it *InTransport) buildChain(cert *x509.Certificate) ([]*x509.Certificate, error) {

	//fmt.Println("InTransport - buildChain() called")

	tmpCert := cert
	var retval []*x509.Certificate
	var lastError error
	for {
		// TODO - set a limit to how many iterations of this loop
		// what's sane?
		_, lastError = tmpCert.Verify(x509.VerifyOptions{
			Roots: it.TLS.RootCAs,
			// We don't care about dns names here
		})
		if lastError == nil {
			break
		}
		var err error
		tmpCert, err = fetchIssuingCert(tmpCert)

		if err != nil {
			return nil, err
		}
		retval = append(retval, tmpCert)
	}
	if lastError != nil {
		return nil, lastError
	}
	return retval, nil
}

func fetchIssuingCert(cert *x509.Certificate) (*x509.Certificate, error) {

	//fmt.Println("fetchIssuingCert() called")
	// this attempts to do two things:
	// 1) avoid stampede problem - minimizes fetches of a cert on cache miss
	// 2) avoid long locks on the outer map.
	if len(cert.IssuingCertificateURL) == 0 {
		return nil, fmt.Errorf("failed to fetch intermediates for %s",
			cert.Subject.CommonName)
	}

	var mapKey string
	if len(cert.AuthorityKeyId) > 0 {
		enc := base64.RawStdEncoding.EncodeToString(cert.AuthorityKeyId)
		mapKey = cert.Issuer.CommonName + ":" + enc
	} else {
		mapKey = cert.Issuer.CommonName
	}
	cc.Lock()
	cce, ok := cc.m[mapKey]
	if ok {
		cc.Unlock()
		cce.Lock()
		crt := cce.cert

		if crt != nil {
			cce.Unlock()
			return crt, nil
		}
	} else {
		cce = new(certCacheEntry)
		cce.Lock()
		cc.m[mapKey] = cce
		cc.Unlock()

	}

	// Once we're here, cce is locked, cc is unlocked
	// defer is nowhere near as slow as the code below
	defer cce.Unlock()

	// I've yet to see more than one IssuingCertificateURL,
	// but just in case...
	var err error
	var fetchedCert *x509.Certificate
	for _, url := range cert.IssuingCertificateURL {
		var resp *http.Response
		resp, err = cc.c.Get(url)
		if err != nil {
			continue
		}

		var raw []byte
		raw, err = ioutil.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			continue
		}
		fetchedCert, err = x509.ParseCertificate(raw)
		if err != nil {
			continue
		}
		cce.cert = fetchedCert
		break
	}
	if err != nil {
		return nil, err
	}
	return fetchedCert, nil
}
