/* Copyright (C) Winston Privacy, Inc - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Richard Stokes <rich@winstonprivacy.com>, March 2018
*/

/* Additional tests for ctx.go which were not in the original implementation.
 */


package goproxy

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"

)

func TestCTX(t *testing.T) {
	Convey("HTTP Protocol Parser works", t, func() {
		// blank request
		header := []byte("")
		So(isHTTP(header), ShouldEqual, false)

		// Normal request
		header = []byte("GET /index.html HTTP/1.1\r\n")
		So(isHTTP(header), ShouldEqual, true)

		// Normal request
		header = []byte("GET /index.html HTTP/1.0\r\n")
		So(isHTTP(header), ShouldEqual, true)

		// Normal request
		header = []byte("GET /index.html HTTP/1.2\r\n")
		So(isHTTP(header), ShouldEqual, true)

		// No trailing line feed
		header = []byte("GET /index.html HTTP/1.1")
		So(isHTTP(header), ShouldEqual, true)

		// Microsoft telemetry protocol
		header = []byte("CNT 1 CON 300\r\n")
		So(isHTTP(header), ShouldEqual, false)

		// Google font files (should work)
		header = []byte("GET /s/materialiconsextended/v39/kJEjBvgX7BgnkSrUwT8UnLVc38YydejYY-oE_LvJ.woff2 HTTP/1.1\r\n")
		So(isHTTP(header), ShouldEqual, true)

		// Stupidly long request (should work)
		header = []byte("GET /service/update2/crx?os=win&arch=x64&os_arch=x86_64&nacl_arch=x86-64&prod=chromecrx&prodchannel=&prodversion=67.0.3396.99&lang=en-US&acceptformat=crx2,crx3&x=id%3Daapocclcgogkmnckokdopfmhonfmgoek%26v%3D0.10%26installedby%3Dinternal%26uc&x=id%3Daohghmighlieiainnegkcijnfilokake%26v%3D0.10%26installedby%3Dinternal%26uc&x=id%3Dapdfllckaahabafndbhieahigkjlhalf%26v%3D14.1%26installedby%3Dinternal%26uc&x=id%3Dblpcfgokakmgnkcojhhkbfbldkacnbeo%26v%3D4.2.8%26installedby%3Dinternal%26uc&x=id%3Dbmnlcjabgnpnenekpadlanbbkooimhnj%26v%3D10.7.8%26installedby%3Dinternal%26uc&x=id%3Dfelcaaldnbdncclmgdcncolpebgiejap%26v%3D1.2%26installedby%3Dinternal%26uc&x=id%3Dghbmnnjooekpmoecnnnilnnbdlolhkhi%26v%3D1.4%26installedby%3Dexternal%26uc&x=id%3Dhdokiejnpimakedhajhdlcegeplioahd%26v%3D4.16.0.13%26installedby%3Dinternal%26uc&x=id%3Dnkbihfbeogaeaoehlefnkodbefgpgknn%26v%3D4.8.0%26installedby%3Dinternal%26uc&x=id%3Dnmmhkkegccagdldgiimedpiccmgmieda%26v%3D1.0.0.4%26installedby%3Dother%26uc&x=id%3Dbkfajajhmehapdgmgjejilcbjmhmebkl%26v%3D1.1.0%26installedby%3Dexternal%26uc&x=id%3Dehlceeijggpdgfcefmipcmdelickjgfg%26v%3D1.0.6%26installedby%3Dexternal%26uc HTTP/1.1\r\n")
		So(isHTTP(header), ShouldEqual, true)
	})
}

