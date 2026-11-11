package bigip

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/stretchr/testify/assert"
)

// authenticate_name goes to BIG-IP as authenticateName on create and on
// update, and is read back into state from it, against a stand-in iControl
// REST server that keeps the profile it was sent.
func TestUnitBigipLtmProfileServerSslAuthenticateName(t *testing.T) {
	t.Setenv("TEEM_DISABLE", "true")

	var mu sync.Mutex
	profile := map[string]interface{}{}
	var sent []string

	setup()
	defer teardown()
	// The provider reads the self IPs when it starts
	mux.HandleFunc("/mgmt/tm/net/self", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{}`)
	})
	mux.HandleFunc("/mgmt/tm/ltm/profile/server-ssl", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &profile)
		sent = append(sent, fmt.Sprint(profile["authenticateName"]))
		// BIG-IP answers with every field, its default where none was sent
		for k, v := range map[string]interface{}{"partition": "Common", "tmOptions": "none", "cipherGroup": "none", "authenticateName": "none"} {
			if _, ok := profile[k]; !ok {
				profile[k] = v
			}
		}
		_ = json.NewEncoder(w).Encode(profile)
	})
	mux.HandleFunc("/mgmt/tm/ltm/profile/server-ssl/~Common~test-serverssl", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case "PATCH":
			changes := map[string]interface{}{}
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &changes)
			for k, v := range changes {
				profile[k] = v
			}
			sent = append(sent, fmt.Sprint(changes["authenticateName"]))
		case "DELETE":
			profile = map[string]interface{}{}
			return
		}
		if len(profile) == 0 {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"code":404,"message":"01020036:3: The requested profile was not found."}`)
			return
		}
		_ = json.NewEncoder(w).Encode(profile)
	})

	config := func(name string) string {
		return fmt.Sprintf(`
resource "bigip_ltm_profile_server_ssl" "test" {
  name              = "/Common/test-serverssl"
  defaults_from     = "/Common/serverssl"
  peer_cert_mode    = "require"
  ca_file           = "/Common/ca-bundle.crt"
  authenticate_name = "%s"
}
`, name)
	}

	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		PreCheck:   func() { testAcctUnitPreCheck(t, server.URL) },
		Providers:  testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: config("3.bc4-beta.com"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ltm_profile_server_ssl.test", "authenticate_name", "3.bc4-beta.com"),
					resource.TestCheckResourceAttr("bigip_ltm_profile_server_ssl.test", "peer_cert_mode", "require"),
				),
			},
			{
				Config: config("www.example.com"),
				Check:  resource.TestCheckResourceAttr("bigip_ltm_profile_server_ssl.test", "authenticate_name", "www.example.com"),
			},
		},
	})

	assert.Equal(t, []string{"3.bc4-beta.com", "www.example.com"}, sent)
}
