package goproxy

import (
	"testing"
)

func TestAlnum(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{
			name:     "Empty String",
			value:    "",
			expected: "",
		}, {
			name: "Multiple Spaces",
			value: "			  		 		 					",
			expected: "",
		}, {
			name:     "All Alpha-Numeric",
			value:    "WinstonPrivacy12345",
			expected: "WinstonPrivacy12345",
		}, {
			name:     "All Alpha-Numeric With Punctuation",
			value:    "!!!Wins;ton[Privacy]-(1)23,45@",
			expected: "WinstonPrivacy12345",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if v := alnum(test.value); v != test.expected {
				t.Fatalf("alnum(%q) returned %q; expected %q", test.value, v, test.expected)
			}
		})
	}
}

// NOTE: we want to return these components from the user agent
// platform
// device type
// browser name
// osname
// os-version
//
// ipad-tablet-chrome-53-ios

func TestUAParse(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{
			name:     "Empty String (blank)",
			value:    "",
			expected: "unknown",
		},
		{
			name: "Multiple Blank Spaces",
			value: "	   				  					",
			expected: "unknown",
		},
		{
			name:     "Simple Mozilla",
			value:    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0 Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0",
			expected: "windows-computer-firefox-windows-6",
		}, {

			name:     "Gibbon",
			value:    "Gibbon/2018.1.6.1/2018.1.6.1: Netflix/2018.1.6.1 (DEVTYPE=NFANDROID2-PRV-FIRETVSTB2015; CERTVER=0)",
			expected: "linux-tv-android",
		}, {
			name:     "TMUF",
			value:    "TMUF",
			expected: "tmuf",
		}, {
			name:     "Microsoft NCSI",
			value:    "Microsoft NCSI",
			expected: "microsoft-ncsi",
		}, {
			name:     "Microsoft Metadata Retrieval Client",
			value:    "MICROSOFT_DEVICE_METADATA_RETRIEVAL_CLIENT",
			expected: "microsoft-device-metadata-retrieval-client",
		}, {
			name:     "CCleaner",
			value:    "CCleaner Update Agent",
			expected: "ccleaner-update-agent",
		}, {
			name:     "Play Ready Client",
			value:    "PlayReadyClient",
			expected: "playreadyclient",
		}, {
			name:     "Server Bag",
			value:    "'server-bag [iPhone OS,12.1.4,16D57,iPhone9,1]'",
			expected: "phone",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if uas := ConvertUserAgentToSignature(test.value); uas != test.expected {
				t.Fatalf("getdevice(%q) returned %q; expected %q", test.value, uas, test.expected)
			}
		})
	}
}
