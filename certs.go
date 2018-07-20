package goproxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/hashicorp/go-rootcerts"
	"time"
)

var GoproxyCaConfig *GoproxyConfig

// This sets up a TLS Config. It's called both by signer.go to set up a server to handle incoming client requests
// as well as by proxy.go to set up the outbound transport. This means that the caller will need to set any
// custom properties if they want to change the behavior. If nil is passed in, it will attempt to load the host's
// root CA set. See: https://github.com/hashicorp/go-rootcerts
func rootCAs(c *rootcerts.Config) *tls.Config {

	// Test code: Print out the system CAs
	start := time.Now()
	certs, err := x509.SystemCertPool()
	end := time.Now()
	if err != nil {
		panic(err)
	}
	fmt.Printf("[INFO] Found %d system CA certs in %v\n", len(certs.Subjects()), end.Sub(start))
	//for _, s := range certs.Subjects() {
	//	fmt.Printf("Found: %s\n", s)
	//}


	t := &tls.Config{
		// RLS 3/15/2018 - Enabling InsecureSkipVerify will result in serious TLS security vulnerabilities. Only use for testing.
		//InsecureSkipVerify: false,

		// This must be set to true for our custom certificate validator to be called. If set to false
		// (the usual setting), then our callback will only be called on successfully validated websites.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
		Renegotiation:      tls.RenegotiateFreelyAsClient,
	}


	err = rootcerts.ConfigureTLS(t, c)
	if err != nil {
		fmt.Println("[Warning] Error loading root certs", err)
	}
	return t
}

func LoadDefaultConfig() error {
	config, err := LoadCAConfig(CA_CERT, CA_KEY)
	if err != nil {
		return fmt.Errorf("Error parsing builtin CA: %s", err.Error())
	}
	GoproxyCaConfig = config
	return nil
}

// Load a CAConfig bundle from by arrays.  You can then load them into
// the proxy with `proxy.SetMITMCertConfig`
func LoadCAConfig(caCert, caKey []byte) (*GoproxyConfig, error) {
	ca, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return nil, err
	}
	priv := ca.PrivateKey

	ca509, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, err
	}
	config, err := NewConfig(ca509, priv)
	return config, err
}

var tlsClientSkipVerify = rootCAs(nil)

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
