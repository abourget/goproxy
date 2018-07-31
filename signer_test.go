package goproxy

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
