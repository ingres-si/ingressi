package tools

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// TestDNSProviderFields decodes the credential keys of every DNS provider in
// the web registry (src/lib/dns-providers.ts, mirrored in
// testdata/dns-provider-fields.json by a unit test) into the bundled Caddy
// module, the same strict way Caddy loads a config. A key the module does not
// know makes Caddy reject the whole config with "unknown field".
func TestDNSProviderFields(t *testing.T) {
	raw, err := os.ReadFile("testdata/dns-provider-fields.json")
	if err != nil {
		t.Fatal(err)
	}
	var providers map[string][]string
	if err := json.Unmarshal(raw, &providers); err != nil {
		t.Fatal(err)
	}
	if len(providers) == 0 {
		t.Fatal("no providers in testdata/dns-provider-fields.json")
	}

	for name, keys := range providers {
		t.Run(name, func(t *testing.T) {
			info, err := caddy.GetModule("dns.providers." + name)
			if err != nil {
				t.Fatalf("module not built in: %v", err)
			}
			for _, key := range keys {
				config, _ := json.Marshal(map[string]string{key: "x"})
				if err := caddy.StrictUnmarshalJSON(config, info.New()); err != nil {
					t.Errorf("field %q: %v", key, err)
				}
			}
		})
	}
}
