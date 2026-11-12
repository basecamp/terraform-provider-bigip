/*
Copyright 2019 F5 Networks Inc.
This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/
package bigip

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	bigip "github.com/f5devcentral/go-bigip"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

// Unit tests for the LTM monitor read - no F5 BIG-IP connection required

const ltmMonitorPathPrefix = "/mgmt/tm/ltm/monitor/"

// ltmMonitorMock is a BIG-IP stand-in that serves /mgmt/tm/ltm/monitor/<type>
// (the list of one type) and /mgmt/tm/ltm/monitor/<type>/<name> (one monitor),
// and records every path requested.
type ltmMonitorMock struct {
	server *httptest.Server
	// monitors maps "<type>/<name as in the URL>" to the JSON body of the monitor
	monitors map[string]string
	// failWith, when not zero, is the status every request is answered with
	failWith int
	// failWithoutMessage, when not zero, is the status every request is answered
	// with, in a body that has a code and no message (the client then reports no error)
	failWithoutMessage int
	// notFoundMessage, when set, replaces the message of the 404 for a missing monitor
	notFoundMessage string
	// failSingleWith, when set, answers every read of one monitor with a 400 carrying this message
	failSingleWith string

	mu       sync.Mutex
	requests []string
}

func newLtmMonitorMock(t *testing.T, monitors map[string]string) *ltmMonitorMock {
	t.Helper()
	mock := &ltmMonitorMock{monitors: monitors}
	mock.server = httptest.NewServer(http.HandlerFunc(mock.handle))
	t.Cleanup(mock.server.Close)
	return mock
}

func (mock *ltmMonitorMock) handle(w http.ResponseWriter, r *http.Request) {
	mock.mu.Lock()
	mock.requests = append(mock.requests, r.Method+" "+r.URL.Path)
	mock.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if mock.failWithoutMessage != 0 {
		w.WriteHeader(mock.failWithoutMessage)
		_, _ = fmt.Fprintf(w, `{"code":%d,"errorStack":[]}`, mock.failWithoutMessage)
		return
	}
	if mock.failWith != 0 {
		w.WriteHeader(mock.failWith)
		_, _ = fmt.Fprintf(w, `{"code":%d,"message":"simulated failure","errorStack":[]}`, mock.failWith)
		return
	}
	if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, ltmMonitorPathPrefix) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, `{"code":404,"message":"Public URI path not registered","errorStack":[]}`)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, ltmMonitorPathPrefix)
	if !strings.Contains(rest, "/") {
		// the list of one monitor type
		var items []string
		for key, body := range mock.monitors {
			if strings.HasPrefix(key, rest+"/") {
				items = append(items, body)
			}
		}
		_, _ = fmt.Fprintf(w, `{"kind":"tm:ltm:monitor:%s:%scollectionstate","items":[%s]}`, rest, rest, strings.Join(items, ","))
		return
	}
	if mock.failSingleWith != "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"code":400,"message":"%s","errorStack":[]}`, mock.failSingleWith)
		return
	}
	body, ok := mock.monitors[rest]
	if !ok {
		name := strings.ReplaceAll(rest[strings.Index(rest, "/")+1:], "~", "/")
		message := fmt.Sprintf("01020036:3: The requested monitor (%s) was not found.", name)
		if mock.notFoundMessage != "" {
			message = mock.notFoundMessage
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, `{"code":404,"message":"%s","errorStack":[],"apiError":3}`, message)
		return
	}
	_, _ = fmt.Fprint(w, body)
}

func (mock *ltmMonitorMock) client() *bigip.BigIP {
	return bigip.NewSession(&bigip.Config{
		Address:  mock.server.URL,
		Username: "xxxx",
		Password: "xxxx",
	})
}

func (mock *ltmMonitorMock) requested() []string {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	return append([]string(nil), mock.requests...)
}

func ltmMonitorReadResourceData(t *testing.T, id string, raw map[string]interface{}) *schema.ResourceData {
	t.Helper()
	d := schema.TestResourceDataRaw(t, resourceBigipLtmMonitor().Schema, raw)
	d.SetId(id)
	return d
}

func TestLtmMonitorType(t *testing.T) {
	cases := []struct {
		parent   string
		wantType string
		wantOk   bool
	}{
		{"/Common/http", "http", true},
		{"/Common/https", "https", true},
		{"/Common/icmp", "icmp", true},
		{"/Common/gateway_icmp", "gateway-icmp", true},
		{"/Common/tcp", "tcp", true},
		{"/Common/tcp_half_open", "tcp-half-open", true},
		{"/Common/ftp", "ftp", true},
		{"/Common/udp", "udp", true},
		{"/Common/postgresql", "postgresql", true},
		{"/Common/mysql", "mysql", true},
		{"/Common/mssql", "mssql", true},
		{"/Common/ldap", "ldap", true},
		{"/Common/smtp", "smtp", true},
		{"/Common/dns", "dns", true},
		{"", "", false},
		{"/Common/my_custom_http", "", false},
		{"/Common/http_head_f5", "", false},
		{"http", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.parent, func(t *testing.T) {
			gotType, gotOk := ltmMonitorType(tc.parent)
			assert.Equal(t, tc.wantType, gotType)
			assert.Equal(t, tc.wantOk, gotOk)
		})
	}
	// every parent the schema accepts has a type
	for parent := range parentMonitors {
		_, ok := ltmMonitorType(parent)
		assert.True(t, ok, "no monitor type for accepted parent %s", parent)
	}
}

func TestLtmMonitorReadFetchesOneMonitorByType(t *testing.T) {
	mock := newLtmMonitorMock(t, map[string]string{
		"http/~Common~test-monitor": `{
			"kind":"tm:ltm:monitor:http:httpstate",
			"name":"test-monitor","partition":"Common","fullPath":"/Common/test-monitor",
			"adaptive":"disabled","adaptiveLimit":200,
			"defaultsFrom":"/Common/http","destination":"*:8080",
			"interval":7,"ipDscp":0,"manualResume":"disabled",
			"recv":"200 OK","recvDisable":"503","reverse":"disabled",
			"send":"GET /up HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n",
			"timeUntilUp":3,"timeout":22,"transparent":"disabled","upInterval":11,
			"username":"monitor-user"
		}`,
		// same name under another type: must not be read
		"tcp/~Common~test-monitor": `{"name":"test-monitor","fullPath":"/Common/test-monitor","defaultsFrom":"/Common/tcp","interval":99}`,
	})
	d := ltmMonitorReadResourceData(t, "/Common/test-monitor", map[string]interface{}{
		"name":   "/Common/test-monitor",
		"parent": "/Common/http",
	})

	diags := resourceBigipLtmMonitorRead(context.Background(), d, mock.client())

	assert.False(t, diags.HasError(), "unexpected error: %v", diags)
	assert.Equal(t, []string{"GET /mgmt/tm/ltm/monitor/http/~Common~test-monitor"}, mock.requested())
	assert.Equal(t, "/Common/test-monitor", d.Id())
	assert.Equal(t, "/Common/test-monitor", d.Get("name"))
	assert.Equal(t, "/Common/http", d.Get("parent"))
	assert.Equal(t, 7, d.Get("interval"))
	assert.Equal(t, 11, d.Get("up_interval"))
	assert.Equal(t, 22, d.Get("timeout"))
	assert.Equal(t, 3, d.Get("time_until_up"))
	assert.Equal(t, "GET /up HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n", d.Get("send"))
	assert.Equal(t, "200 OK", d.Get("receive"))
	assert.Equal(t, "503", d.Get("receive_disable"))
	assert.Equal(t, "*:8080", d.Get("destination"))
	assert.Equal(t, "disabled", d.Get("reverse"))
	assert.Equal(t, "disabled", d.Get("transparent"))
	assert.Equal(t, "disabled", d.Get("manual_resume"))
	assert.Equal(t, "disabled", d.Get("adaptive"))
	assert.Equal(t, 200, d.Get("adaptive_limit"))
	assert.Equal(t, "monitor-user", d.Get("username"))
	// not an https monitor: compatibility keeps its configured (default) value
	assert.Equal(t, "enabled", d.Get("compatibility"))
}

func TestLtmMonitorReadTypeInPath(t *testing.T) {
	cases := []struct {
		parent   string
		wantPath string
	}{
		{"/Common/https", "/mgmt/tm/ltm/monitor/https/~Common~m"},
		{"/Common/gateway_icmp", "/mgmt/tm/ltm/monitor/gateway-icmp/~Common~m"},
		{"/Common/tcp_half_open", "/mgmt/tm/ltm/monitor/tcp-half-open/~Common~m"},
		{"/Common/mysql", "/mgmt/tm/ltm/monitor/mysql/~Common~m"},
		// dns is not one of the types Monitors() lists; it is only readable by type
		{"/Common/dns", "/mgmt/tm/ltm/monitor/dns/~Common~m"},
	}
	for _, tc := range cases {
		t.Run(tc.parent, func(t *testing.T) {
			key := strings.TrimPrefix(tc.wantPath, ltmMonitorPathPrefix)
			mock := newLtmMonitorMock(t, map[string]string{
				key: fmt.Sprintf(`{"name":"m","fullPath":"/Common/m","defaultsFrom":"%s","interval":4,"timeout":13,"compatibility":"disabled","sslProfile":"/Common/serverssl"}`, tc.parent),
			})
			d := ltmMonitorReadResourceData(t, "/Common/m", map[string]interface{}{
				"name":   "/Common/m",
				"parent": tc.parent,
			})

			diags := resourceBigipLtmMonitorRead(context.Background(), d, mock.client())

			assert.False(t, diags.HasError(), "unexpected error: %v", diags)
			assert.Equal(t, []string{"GET " + tc.wantPath}, mock.requested())
			assert.Equal(t, "/Common/m", d.Id())
			assert.Equal(t, tc.parent, d.Get("parent"))
			assert.Equal(t, 4, d.Get("interval"))
			assert.Equal(t, 13, d.Get("timeout"))
			if tc.parent == "/Common/https" {
				assert.Equal(t, "disabled", d.Get("compatibility"))
				assert.Equal(t, "/Common/serverssl", d.Get("ssl_profile"))
			} else {
				assert.Equal(t, "enabled", d.Get("compatibility"))
				assert.Equal(t, "", d.Get("ssl_profile"))
			}
		})
	}
}

func TestLtmMonitorReadCustomParentKeepsType(t *testing.T) {
	mock := newLtmMonitorMock(t, map[string]string{
		"http/~Common~child": `{"name":"child","fullPath":"/Common/child","defaultsFrom":"/Common/my-base-http","interval":5,"timeout":16}`,
	})
	d := ltmMonitorReadResourceData(t, "/Common/child", map[string]interface{}{
		"name":          "/Common/child",
		"parent":        "/Common/http",
		"custom_parent": "/Common/my-base-http",
	})

	diags := resourceBigipLtmMonitorRead(context.Background(), d, mock.client())

	assert.False(t, diags.HasError(), "unexpected error: %v", diags)
	assert.Equal(t, []string{"GET /mgmt/tm/ltm/monitor/http/~Common~child"}, mock.requested())
	assert.Equal(t, "/Common/http", d.Get("parent"))
	assert.Equal(t, "/Common/my-base-http", d.Get("custom_parent"))
}

// A monitor that is gone from the device fails the read with the same error
// as before and stays in state.
func TestLtmMonitorReadNotFoundIsAnError(t *testing.T) {
	mock := newLtmMonitorMock(t, map[string]string{
		"http/~Common~other": `{"name":"other","fullPath":"/Common/other","defaultsFrom":"/Common/http","interval":5}`,
	})
	d := ltmMonitorReadResourceData(t, "/Common/gone", map[string]interface{}{
		"name":   "/Common/gone",
		"parent": "/Common/http",
	})

	diags := resourceBigipLtmMonitorRead(context.Background(), d, mock.client())

	if assert.Len(t, diags, 1) {
		assert.Equal(t, "Couldn't find LTM Monitor /Common/gone ", diags[0].Summary)
	}
	// one read by type and nothing else: a refresh never lists monitors
	assert.Equal(t, []string{"GET /mgmt/tm/ltm/monitor/http/~Common~gone"}, mock.requested())
	assert.Equal(t, "/Common/gone", d.Id())
}

// A monitor recreated outside Terraform under another type keeps its full path
// but is not found under the type in state. The read does not go looking for
// it under other types: it is the not-found error, and state is left alone.
func TestLtmMonitorReadFoundUnderAnotherTypeIsNotFound(t *testing.T) {
	mock := newLtmMonitorMock(t, map[string]string{
		"tcp/~Common~retyped": `{"name":"retyped","fullPath":"/Common/retyped","defaultsFrom":"/Common/tcp","interval":6,"timeout":19}`,
	})
	d := ltmMonitorReadResourceData(t, "/Common/retyped", map[string]interface{}{
		"name":   "/Common/retyped",
		"parent": "/Common/http",
	})

	diags := resourceBigipLtmMonitorRead(context.Background(), d, mock.client())

	if assert.Len(t, diags, 1) {
		assert.Equal(t, "Couldn't find LTM Monitor /Common/retyped ", diags[0].Summary)
	}
	assert.Equal(t, []string{"GET /mgmt/tm/ltm/monitor/http/~Common~retyped"}, mock.requested())
	assert.Equal(t, "/Common/retyped", d.Id())
	assert.Equal(t, "/Common/http", d.Get("parent"))
}

// Not found is decided by the 404 status, whatever the wording of the message.
func TestLtmMonitorRead404WithOtherWordingIsNotFound(t *testing.T) {
	mock := newLtmMonitorMock(t, map[string]string{
		"http/~Common~other": `{"name":"other","fullPath":"/Common/other","defaultsFrom":"/Common/http","interval":5}`,
	})
	mock.notFoundMessage = "Public URI path not registered"
	d := ltmMonitorReadResourceData(t, "/Common/test-monitor", map[string]interface{}{
		"name":   "/Common/test-monitor",
		"parent": "/Common/http",
	})

	diags := resourceBigipLtmMonitorRead(context.Background(), d, mock.client())

	if assert.Len(t, diags, 1) {
		assert.Equal(t, "Couldn't find LTM Monitor /Common/test-monitor ", diags[0].Summary)
	}
	assert.Equal(t, []string{"GET /mgmt/tm/ltm/monitor/http/~Common~test-monitor"}, mock.requested())
	assert.Equal(t, "/Common/test-monitor", d.Id())
}

// A read by type that answers with another monitor is an error, and nothing
// of that monitor reaches state.
func TestLtmMonitorReadAnotherMonitorsBodyIsAnError(t *testing.T) {
	mock := newLtmMonitorMock(t, map[string]string{
		"http/~Common~test-monitor": `{"name":"other","fullPath":"/Common/other","defaultsFrom":"/Common/http","interval":77}`,
	})
	d := ltmMonitorReadResourceData(t, "/Common/test-monitor", map[string]interface{}{
		"name":     "/Common/test-monitor",
		"parent":   "/Common/http",
		"interval": 5,
	})

	diags := resourceBigipLtmMonitorRead(context.Background(), d, mock.client())

	if assert.Len(t, diags, 1) {
		assert.Equal(t, `reading LTM Monitor /Common/test-monitor as type http returned "/Common/other" instead`, diags[0].Summary)
	}
	assert.Equal(t, []string{"GET /mgmt/tm/ltm/monitor/http/~Common~test-monitor"}, mock.requested())
	assert.Equal(t, "/Common/test-monitor", d.Id())
	assert.Equal(t, 5, d.Get("interval"))
}

// A failure that is not a 404 is reported as it is, even when its message
// says "not found": it is not the not-found error, and there is no fallback.
func TestLtmMonitorReadFailureThatIsNot404IsReported(t *testing.T) {
	mock := newLtmMonitorMock(t, map[string]string{
		"http/~Common~test-monitor": `{"name":"test-monitor","fullPath":"/Common/test-monitor","defaultsFrom":"/Common/http","interval":8}`,
	})
	mock.failSingleWith = "01070734:3: Configuration error: profile /Common/x not found"
	d := ltmMonitorReadResourceData(t, "/Common/test-monitor", map[string]interface{}{
		"name":   "/Common/test-monitor",
		"parent": "/Common/http",
	})

	diags := resourceBigipLtmMonitorRead(context.Background(), d, mock.client())

	if assert.Len(t, diags, 1) {
		assert.Equal(t, "01070734:3: Configuration error: profile /Common/x not found", diags[0].Summary)
	}
	assert.Equal(t, []string{"GET /mgmt/tm/ltm/monitor/http/~Common~test-monitor"}, mock.requested())
	assert.Equal(t, "/Common/test-monitor", d.Id())
}

func TestLtmMonitorReadServerErrorIsReported(t *testing.T) {
	mock := newLtmMonitorMock(t, map[string]string{})
	mock.failWith = http.StatusInternalServerError
	d := ltmMonitorReadResourceData(t, "/Common/test-monitor", map[string]interface{}{
		"name":   "/Common/test-monitor",
		"parent": "/Common/http",
	})

	diags := resourceBigipLtmMonitorRead(context.Background(), d, mock.client())

	if assert.Len(t, diags, 1) {
		assert.Equal(t, "simulated failure", diags[0].Summary)
	}
	assert.Equal(t, []string{"GET /mgmt/tm/ltm/monitor/http/~Common~test-monitor"}, mock.requested())
	assert.Equal(t, "/Common/test-monitor", d.Id())
}

// A 404 without a message is still not found: the status decides.
func TestLtmMonitorRead404WithoutMessageIsNotFound(t *testing.T) {
	mock := newLtmMonitorMock(t, map[string]string{})
	mock.failWithoutMessage = http.StatusNotFound
	d := ltmMonitorReadResourceData(t, "/Common/test-monitor", map[string]interface{}{
		"name":   "/Common/test-monitor",
		"parent": "/Common/http",
	})

	diags := resourceBigipLtmMonitorRead(context.Background(), d, mock.client())

	if assert.Len(t, diags, 1) {
		assert.Equal(t, "Couldn't find LTM Monitor /Common/test-monitor ", diags[0].Summary)
	}
	assert.Equal(t, "/Common/test-monitor", d.Id())
}

// A failure without a message, which the client does not report as an error,
// is still an error and sets nothing in state.
func TestLtmMonitorReadFailureWithoutMessageIsAnError(t *testing.T) {
	mock := newLtmMonitorMock(t, map[string]string{})
	mock.failWithoutMessage = http.StatusForbidden
	d := ltmMonitorReadResourceData(t, "/Common/test-monitor", map[string]interface{}{
		"name":     "/Common/test-monitor",
		"parent":   "/Common/http",
		"interval": 5,
	})

	diags := resourceBigipLtmMonitorRead(context.Background(), d, mock.client())

	if assert.Len(t, diags, 1) {
		assert.Equal(t, "reading LTM Monitor /Common/test-monitor as type http failed with code 403", diags[0].Summary)
	}
	assert.Equal(t, "/Common/test-monitor", d.Id())
	assert.Equal(t, 5, d.Get("interval"))
}

// A parent in state that is not a built-in type does not say what type the
// monitor is. The read says so instead of listing every monitor to find it.
func TestLtmMonitorReadParentNotBuiltInIsAnError(t *testing.T) {
	mock := newLtmMonitorMock(t, map[string]string{
		"http/~Common~child": `{"name":"child","fullPath":"/Common/child","defaultsFrom":"/Common/my-base-http","interval":5}`,
	})
	d := ltmMonitorReadResourceData(t, "/Common/child", map[string]interface{}{
		"name":   "/Common/child",
		"parent": "/Common/my-base-http",
	})

	diags := resourceBigipLtmMonitorRead(context.Background(), d, mock.client())

	if assert.Len(t, diags, 1) {
		assert.Contains(t, diags[0].Summary, "LTM Monitor /Common/child has parent /Common/my-base-http in state, which is not a built-in monitor type")
	}
	assert.Empty(t, mock.requested())
	assert.Equal(t, "/Common/child", d.Id())
	assert.Equal(t, "/Common/my-base-http", d.Get("parent"))
}

// With no parent in state (terraform import) the type is unknown, so the read
// still goes through the list of all monitors and finds the monitor by full path.
func TestLtmMonitorReadWithoutParentListsMonitors(t *testing.T) {
	mock := newLtmMonitorMock(t, map[string]string{
		"http/~Common~other":   `{"name":"other","fullPath":"/Common/other","defaultsFrom":"/Common/http","interval":5}`,
		"tcp/~Common~imported": `{"name":"imported","fullPath":"/Common/imported","defaultsFrom":"/Common/tcp","interval":9,"timeout":28}`,
	})
	d := ltmMonitorReadResourceData(t, "/Common/imported", map[string]interface{}{})

	diags := resourceBigipLtmMonitorRead(context.Background(), d, mock.client())

	assert.False(t, diags.HasError(), "unexpected error: %v", diags)
	requests := mock.requested()
	assert.Len(t, requests, 13)
	for _, request := range requests {
		assert.NotContains(t, request, "~", "expected only list requests, got %s", request)
	}
	assert.Equal(t, "/Common/imported", d.Id())
	assert.Equal(t, "/Common/tcp", d.Get("parent"))
	assert.Equal(t, 9, d.Get("interval"))
	assert.Equal(t, 28, d.Get("timeout"))
}

func TestLtmMonitorReadWithoutParentNotFoundIsAnError(t *testing.T) {
	mock := newLtmMonitorMock(t, map[string]string{
		"http/~Common~other": `{"name":"other","fullPath":"/Common/other","defaultsFrom":"/Common/http","interval":5}`,
	})
	d := ltmMonitorReadResourceData(t, "/Common/missing", map[string]interface{}{})

	diags := resourceBigipLtmMonitorRead(context.Background(), d, mock.client())

	assert.True(t, diags.HasError())
	assert.Equal(t, "/Common/missing", d.Id())
}
