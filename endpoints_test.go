package rypt

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"reflect"
	"testing"
	"time"
)

// endpointCase is one call of a Client method against the fake API.
type endpointCase struct {
	name   string // the subtest name; the method's name
	op     string // the OpenAPI operationId
	method string
	path   string // the escaped path the request must go to
	query  string // the expected raw query, keys sorted
	body   string // the expected request body as JSON, or "" for none
	status int    // the success status the API answers with
	reply  any    // the response body, or nil for none
	retry  retryPolicy
	noAuth bool
	call   func(context.Context, *Client) (any, error)
	want   any // the expected result
}

var b64 = base64.StdEncoding.EncodeToString

// endpointCases returns a case for every operation the client makes, with
// the request each must send and the result each must decode.
func endpointCases(t *testing.T) []endpointCase {
	created := mustTime(t, "2026-09-16T10:00:00.123456Z")
	retiring := mustTime(t, "2026-10-21T09:15:00.25Z")
	deleted := mustTime(t, "2026-10-01T12:00:00Z")
	destroy := mustTime(t, "2026-10-08T12:00:00Z")

	keyJSON := map[string]any{
		"id":                  keyID,
		"container_id":        containerID,
		"name":                "prod-database",
		"tier":                "software",
		"versions":            []string{"1", "2", "3", "4"},
		"primary_version":     "4",
		"retiring_versions":   []any{map[string]any{"version": "1", "destroy_after": "2026-10-21T09:15:00.25Z"}},
		"created_at":          "2026-09-16T10:00:00.123456Z",
		"state":               "active",
		"delete_requested_at": nil,
		"destroy_after":       nil,
	}
	key := &Key{
		ID:               keyID,
		ContainerID:      containerID,
		Name:             "prod-database",
		Tier:             TierSoftware,
		Versions:         []string{"1", "2", "3", "4"},
		PrimaryVersion:   "4",
		RetiringVersions: []RetiringVersion{{Version: "1", DestroyAfter: retiring}},
		CreatedAt:        created,
		State:            KeyActive,
	}
	pendingJSON := map[string]any{}
	for k, v := range keyJSON {
		pendingJSON[k] = v
	}
	pendingJSON["state"] = "pending_deletion"
	pendingJSON["delete_requested_at"] = "2026-10-01T12:00:00Z"
	pendingJSON["destroy_after"] = "2026-10-08T12:00:00Z"
	pending := *key
	pending.State = KeyPendingDeletion
	pending.DeleteRequestedAt = &deleted
	pending.DestroyAfter = &destroy

	auditJSON := map[string]any{
		"id": 42, "ts": "2026-09-16T10:00:00.123456Z", "key_id": keyID,
		"api_token_id": tokenID, "user_id": nil, "op": "encrypt", "kms_version": "3",
		"result": "error", "error_code": "action_not_allowed", "request_id": "018f8a0e",
		"src_ip": "10.0.0.7", "bytes": 11, "kms_us": nil,
	}
	audit := AuditEvent{
		ID: 42, Time: created, KeyID: keyID, APITokenID: tokenID, Op: OpEncrypt,
		KMSVersion: "3", Result: ResultError, ErrorCode: CodeActionNotAllowed,
		RequestID: "018f8a0e", SourceIP: "10.0.0.7", Bytes: ptr[int64](11),
	}

	tokenJSON := map[string]any{
		"id": tokenID, "name": "production", "created_by_user_id": userID,
		"created_at": "2026-09-16T10:00:00.123456Z", "revoked_at": nil,
		"container_id": containerID, "firewall_id": nil, "key_ids": nil,
		"allowed_actions": []string{"decrypt", "encrypt"},
	}
	token := APIToken{
		ID: tokenID, Name: "production", CreatedByUserID: userID, CreatedAt: created,
		ContainerID: containerID, AllowedActions: []Action{ActionDecrypt, ActionEncrypt},
	}
	chainJSON := map[string]any{"seq": 5, "hash": "07d1c0ffee5e7c0de0ddba11ab1e5eedfacade0123456789abcdef0123456789"}
	chain := ChainHead{Seq: 5, Hash: "07d1c0ffee5e7c0de0ddba11ab1e5eedfacade0123456789abcdef0123456789"}
	updatedJSON := map[string]any{}
	for k, v := range tokenJSON {
		updatedJSON[k] = v
	}
	updatedJSON["firewall_id"] = firewallID
	updatedJSON["key_ids"] = []string{keyID}
	updatedJSON["permission_chain_head"] = chainJSON
	updated := &UpdatedAPIToken{APIToken: token, PermissionChainHead: chain}
	updated.FirewallID = firewallID
	updated.KeyIDs = []string{keyID}

	containerJSON := map[string]any{"id": containerID, "name": "Default", "is_default": true, "created_at": "2026-09-16T10:00:00.123456Z"}
	container := Container{ID: containerID, Name: "Default", IsDefault: true, CreatedAt: created}
	firewallJSON := map[string]any{
		"id": firewallID, "container_id": containerID, "name": "office",
		"allowed_ips": []string{"203.0.113.0/24", "2001:db8::/32"}, "created_at": "2026-09-16T10:00:00.123456Z",
	}
	firewall := Firewall{
		ID: firewallID, ContainerID: containerID, Name: "office",
		AllowedIPs: []string{"203.0.113.0/24", "2001:db8::/32"}, CreatedAt: created,
	}

	dek := bytes.Repeat([]byte{7}, 32)
	dek16 := bytes.Repeat([]byte{9}, 16)

	return []endpointCase{
		{
			name: "CreateKey", op: "createKey", method: "POST", path: "/v1/keys",
			body:   `{"name":"prod-database","tier":"software","container_id":"` + containerID + `"}`,
			status: http.StatusCreated, reply: keyJSON, retry: retryIfUnprocessed,
			call: func(ctx context.Context, c *Client) (any, error) {
				return c.CreateKey(ctx, &CreateKeyParams{Name: "prod-database", Tier: TierSoftware, ContainerID: containerID})
			},
			want: key,
		},
		{
			name: "ListKeys", op: "listKeys", method: "GET", path: "/v1/keys",
			status: http.StatusOK, reply: []any{keyJSON, pendingJSON}, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) { return c.ListKeys(ctx) },
			want: []Key{*key, pending},
		},
		{
			name: "GetKey", op: "getKey", method: "GET", path: "/v1/keys/" + keyID,
			status: http.StatusOK, reply: pendingJSON, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) { return c.GetKey(ctx, keyID) },
			want: &pending,
		},
		{
			name: "RenameKey", op: "renameKey", method: "PATCH", path: "/v1/keys/" + keyID,
			body:   `{"name":"orders-database"}`,
			status: http.StatusOK, reply: keyJSON, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) { return c.RenameKey(ctx, keyID, "orders-database") },
			want: key,
		},
		{
			name: "DeleteKey", op: "deleteKey", method: "DELETE", path: "/v1/keys/" + keyID,
			status: http.StatusOK, reply: pendingJSON, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) { return c.DeleteKey(ctx, keyID) },
			want: &pending,
		},
		{
			name: "RotateKey", op: "rotateKey", method: "POST", path: "/v1/keys/" + keyID + "/rotate",
			status: http.StatusOK, reply: keyJSON, retry: retryIfUnprocessed,
			call: func(ctx context.Context, c *Client) (any, error) { return c.RotateKey(ctx, keyID) },
			want: key,
		},
		{
			name: "RestoreKey", op: "restoreKey", method: "POST", path: "/v1/keys/" + keyID + "/restore",
			status: http.StatusOK, reply: keyJSON, retry: retryIfUnprocessed,
			call: func(ctx context.Context, c *Client) (any, error) { return c.RestoreKey(ctx, keyID) },
			want: key,
		},
		{
			name: "DestroyKey", op: "destroyKey", method: "POST", path: "/v1/keys/" + keyID + "/destroy",
			status: http.StatusNoContent, retry: retryIfUnprocessed,
			call: func(ctx context.Context, c *Client) (any, error) { return nil, c.DestroyKey(ctx, keyID) },
		},
		{
			name: "Encrypt", op: "encrypt", method: "POST", path: "/v1/keys/" + keyID + "/encrypt",
			body:   `{"plaintext":"` + b64([]byte("hello world")) + `","aad":"` + b64([]byte("table=users")) + `"}`,
			status: http.StatusOK, reply: map[string]any{"ciphertext": b64([]byte("CT"))}, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) {
				return c.Encrypt(ctx, keyID, []byte("hello world"), []byte("table=users"))
			},
			want: []byte("CT"),
		},
		{
			name: "Decrypt", op: "decrypt", method: "POST", path: "/v1/keys/" + keyID + "/decrypt",
			body:   `{"ciphertext":"` + b64([]byte("CT")) + `"}`,
			status: http.StatusOK, reply: map[string]any{"plaintext": b64([]byte("hello world"))}, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) { return c.Decrypt(ctx, keyID, []byte("CT"), nil) },
			want: []byte("hello world"),
		},
		{
			name: "GenerateDataKey", op: "wrap", method: "POST", path: "/v1/keys/" + keyID + "/wrap",
			body:   `{"aad":"` + b64([]byte("object=42")) + `"}`,
			status: http.StatusOK, reply: map[string]any{"dek": b64(dek), "wrapped": b64([]byte("W"))}, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) {
				return c.GenerateDataKey(ctx, keyID, []byte("object=42"))
			},
			want: &DataKey{Plaintext: dek, Wrapped: []byte("W")},
		},
		{
			name: "Wrap", op: "wrap", method: "POST", path: "/v1/keys/" + keyID + "/wrap",
			body:   `{"dek":"` + b64(dek16) + `"}`,
			status: http.StatusOK, reply: map[string]any{"wrapped": b64([]byte("W16"))}, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) { return c.Wrap(ctx, keyID, dek16, nil) },
			want: []byte("W16"),
		},
		{
			name: "Unwrap", op: "unwrap", method: "POST", path: "/v1/keys/" + keyID + "/unwrap",
			body:   `{"wrapped":"` + b64([]byte("W")) + `","aad":"` + b64([]byte("object=42")) + `"}`,
			status: http.StatusOK, reply: map[string]any{"dek": b64(dek)}, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) {
				return c.Unwrap(ctx, keyID, []byte("W"), []byte("object=42"))
			},
			want: dek,
		},
		{
			name: "Rewrap", op: "rewrap", method: "POST", path: "/v1/keys/" + keyID + "/rewrap",
			body:   `{"ciphertext":"` + b64([]byte("CT")) + `"}`,
			status: http.StatusOK, reply: map[string]any{"ciphertext": b64([]byte("CT2"))}, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) { return c.Rewrap(ctx, keyID, []byte("CT"), nil) },
			want: []byte("CT2"),
		},
		{
			name: "ListAuditEvents", op: "listAuditEvents", method: "GET", path: "/v1/keys/" + keyID + "/audit",
			query:  "limit=1000&since=2026-09-16T10%3A00%3A00.123456Z&until=2026-10-01T12%3A00%3A00Z",
			status: http.StatusOK, reply: []any{auditJSON}, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) {
				since := created.In(time.FixedZone("UTC+2", 2*60*60))
				return c.ListAuditEvents(ctx, keyID, &AuditEventsParams{Since: since, Until: deleted, Limit: 1000})
			},
			want: []AuditEvent{audit},
		},
		{
			name: "Usage", op: "getUsage", method: "GET", path: "/v1/usage", query: "period=2026-09",
			status: http.StatusOK, retry: retryIfTransient,
			reply: []any{map[string]any{
				"key_id": keyID, "container_id": containerID, "ops": 1234, "overage_ops": 0, "cap": 100000, "allowance": 100000,
			}},
			call: func(ctx context.Context, c *Client) (any, error) { return c.Usage(ctx, "2026-09") },
			want: []UsageLine{{KeyID: keyID, ContainerID: containerID, Ops: 1234, Cap: 100000, Allowance: 100000}},
		},
		{
			name: "Me", op: "getMe", method: "GET", path: "/v1/me",
			status: http.StatusOK, retry: retryIfTransient,
			reply: map[string]any{
				"user":   map[string]any{"id": userID, "email": nil, "name": "Ada", "created_at": "2026-09-16T10:00:00.123456Z"},
				"tenant": map[string]any{"id": containerID, "name": "ada@example.com"},
				"role":   "owner",
			},
			call: func(ctx context.Context, c *Client) (any, error) { return c.Me(ctx) },
			want: &Me{
				User:   User{ID: userID, Name: "Ada", CreatedAt: created},
				Tenant: Tenant{ID: containerID, Name: "ada@example.com"},
				Role:   RoleOwner,
			},
		},
		{
			name: "CreateAPIToken", op: "createApiToken", method: "POST", path: "/v1/api-tokens",
			body:   `{"name":"production","allowed_actions":["encrypt","decrypt"]}`,
			status: http.StatusCreated, retry: retryIfUnprocessed,
			reply: map[string]any{
				"id": tokenID, "name": "production", "container_id": containerID, "prefix": "K3pQ7xTa",
				"created_at": "2026-09-16T10:00:00.123456Z", "allowed_actions": []string{"decrypt", "encrypt"},
				"permission_chain_head": chainJSON, "token": testToken,
			},
			call: func(ctx context.Context, c *Client) (any, error) {
				return c.CreateAPIToken(ctx, &CreateAPITokenParams{Name: "production", AllowedActions: []Action{ActionEncrypt, ActionDecrypt}})
			},
			want: &CreatedAPIToken{
				ID: tokenID, Name: "production", ContainerID: containerID, Prefix: "K3pQ7xTa", CreatedAt: created,
				AllowedActions: []Action{ActionDecrypt, ActionEncrypt}, PermissionChainHead: chain, Token: testToken,
			},
		},
		{
			name: "ListAPITokens", op: "listApiTokens", method: "GET", path: "/v1/api-tokens",
			status: http.StatusOK, reply: []any{tokenJSON}, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) { return c.ListAPITokens(ctx) },
			want: []APIToken{token},
		},
		{
			name: "UpdateAPIToken", op: "updateApiToken", method: "PATCH", path: "/v1/api-tokens/" + tokenID,
			body:   `{"firewall_id":"` + firewallID + `","key_ids":["` + keyID + `"]}`,
			status: http.StatusOK, reply: updatedJSON, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) {
				return c.UpdateAPIToken(ctx, tokenID, &UpdateAPITokenParams{FirewallID: Set(firewallID), KeyIDs: Set([]string{keyID})})
			},
			want: updated,
		},
		{
			name: "RevokeAPIToken", op: "revokeApiToken", method: "DELETE", path: "/v1/api-tokens/" + tokenID,
			status: http.StatusNoContent, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) { return nil, c.RevokeAPIToken(ctx, tokenID) },
		},
		{
			name: "ListContainers", op: "listContainers", method: "GET", path: "/v1/containers",
			status: http.StatusOK, reply: []any{containerJSON}, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) { return c.ListContainers(ctx) },
			want: []Container{container},
		},
		{
			name: "CreateContainer", op: "createContainer", method: "POST", path: "/v1/containers",
			body:   `{"name":"staging"}`,
			status: http.StatusCreated, reply: containerJSON, retry: retryIfUnprocessed,
			call: func(ctx context.Context, c *Client) (any, error) { return c.CreateContainer(ctx, "staging") },
			want: &container,
		},
		{
			name: "RenameContainer", op: "renameContainer", method: "PATCH", path: "/v1/containers/" + containerID,
			body:   `{"name":"production"}`,
			status: http.StatusOK, reply: containerJSON, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) {
				return c.RenameContainer(ctx, containerID, "production")
			},
			want: &container,
		},
		{
			name: "DeleteContainer", op: "deleteContainer", method: "DELETE", path: "/v1/containers/" + containerID,
			status: http.StatusNoContent, retry: retryIfUnprocessed,
			call: func(ctx context.Context, c *Client) (any, error) { return nil, c.DeleteContainer(ctx, containerID) },
		},
		{
			name: "PermissionChain", op: "getPermissionChain", method: "GET",
			path:   "/v1/containers/" + containerID + "/permission-chain",
			status: http.StatusOK, reply: map[string]any{"container_id": containerID, "head": chainJSON}, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) { return c.PermissionChain(ctx, containerID) },
			want: &PermissionChain{ContainerID: containerID, Head: chain},
		},
		{
			name: "ListFirewalls", op: "listFirewalls", method: "GET", path: "/v1/firewalls",
			status: http.StatusOK, reply: []any{firewallJSON}, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) { return c.ListFirewalls(ctx) },
			want: []Firewall{firewall},
		},
		{
			name: "CreateFirewall", op: "createFirewall", method: "POST", path: "/v1/firewalls",
			body:   `{"name":"office","allowed_ips":["203.0.113.0/24","2001:db8::/32"]}`,
			status: http.StatusCreated, reply: firewallJSON, retry: retryIfUnprocessed,
			call: func(ctx context.Context, c *Client) (any, error) {
				return c.CreateFirewall(ctx, &CreateFirewallParams{Name: "office", AllowedIPs: []string{"203.0.113.0/24", "2001:db8::/32"}})
			},
			want: &firewall,
		},
		{
			name: "UpdateFirewall", op: "updateFirewall", method: "PATCH", path: "/v1/firewalls/" + firewallID,
			body:   `{"allowed_ips":["198.51.100.0/24"]}`,
			status: http.StatusOK, reply: firewallJSON, retry: retryIfTransient,
			call: func(ctx context.Context, c *Client) (any, error) {
				return c.UpdateFirewall(ctx, firewallID, &UpdateFirewallParams{AllowedIPs: []string{"198.51.100.0/24"}})
			},
			want: &firewall,
		},
		{
			name: "DeleteFirewall", op: "deleteFirewall", method: "DELETE", path: "/v1/firewalls/" + firewallID,
			status: http.StatusNoContent, retry: retryIfUnprocessed,
			call: func(ctx context.Context, c *Client) (any, error) { return nil, c.DeleteFirewall(ctx, firewallID) },
		},
		{
			name: "Billing", op: "getBilling", method: "GET", path: "/v1/billing",
			status: http.StatusOK, retry: retryIfTransient,
			reply: map[string]any{
				"status": "active", "period": "2026-09", "cancel_at": "2026-10-08T12:00:00Z",
				"estimate": map[string]any{"currency": "usd", "total_cents": 612, "lines": []any{map[string]any{
					"tier": "wrapped", "key_months": 2, "key_days": 60, "days_in_period": 30, "fee_cents": 300,
					"overage_ops": 12345, "overage_millicents_per_op": 1, "fee_amount_cents": 600,
					"overage_amount_cents": 12, "amount_cents": 612,
				}}},
			},
			call: func(ctx context.Context, c *Client) (any, error) { return c.Billing(ctx) },
			want: &Billing{
				Status: BillingActive, Period: "2026-09", CancelAt: &destroy,
				Estimate: BillingEstimate{Currency: "usd", TotalCents: 612, Lines: []BillingLine{{
					Tier: TierWrapped, KeyMonths: 2, KeyDays: 60, DaysInPeriod: 30, FeeCents: 300,
					OverageOps: 12345, OverageMillicentsPerOp: 1, FeeAmountCents: 600,
					OverageAmountCents: 12, AmountCents: 612,
				}}},
			},
		},
		{
			name: "CreateCheckoutSession", op: "createCheckoutSession", method: "POST", path: "/v1/billing/checkout",
			status: http.StatusOK, reply: map[string]any{"url": "https://checkout.stripe.com/c/pay/cs_test"}, retry: retryIfUnprocessed,
			call: func(ctx context.Context, c *Client) (any, error) { return c.CreateCheckoutSession(ctx) },
			want: &BillingSession{URL: "https://checkout.stripe.com/c/pay/cs_test"},
		},
		{
			name: "CreatePortalSession", op: "createPortalSession", method: "POST", path: "/v1/billing/portal",
			status: http.StatusOK, reply: map[string]any{"url": "https://billing.stripe.com/p/session/test"}, retry: retryIfUnprocessed,
			call: func(ctx context.Context, c *Client) (any, error) { return c.CreatePortalSession(ctx) },
			want: &BillingSession{URL: "https://billing.stripe.com/p/session/test"},
		},
		{
			name: "Health", op: "healthzV1", method: "GET", path: "/v1/healthz",
			status: http.StatusOK, reply: map[string]any{"status": "ok"}, retry: retryIfTransient, noAuth: true,
			call: func(ctx context.Context, c *Client) (any, error) { return nil, c.Health(ctx) },
		},
	}
}

// reply returns the responder for the case's success.
func (tc *endpointCase) responder() responder {
	if tc.reply == nil {
		return noContent()
	}
	return jsonReply(tc.status, tc.reply)
}

// TestEndpoints checks the request every method sends and the result it
// decodes.
func TestEndpoints(t *testing.T) {
	for _, tc := range endpointCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeAPI(t)
			api.script(tc.responder())
			got, err := tc.call(t.Context(), api.client(WithUserAgent("test-app/1.0")))
			if err != nil {
				t.Fatalf("call failed: %v", err)
			}
			if tc.want != nil && !reflect.DeepEqual(got, tc.want) {
				t.Errorf("result\n got %s\nwant %s", sprint(got), sprint(tc.want))
			}

			reqs := api.requests()
			if len(reqs) != 1 {
				t.Fatalf("sent %d requests, want 1", len(reqs))
			}
			req := reqs[0]
			if req.method != tc.method || req.path != tc.path {
				t.Errorf("request %s %s, want %s %s", req.method, req.path, tc.method, tc.path)
			}
			if req.query != tc.query {
				t.Errorf("query %q, want %q", req.query, tc.query)
			}
			if got, want := formatJSON(t, req.body), formatJSON(t, []byte(tc.body)); got != want {
				t.Errorf("body %s, want %s", got, want)
			}

			wantAuth := "Bearer " + testToken
			if tc.noAuth {
				wantAuth = ""
			}
			if got := req.header.Get("Authorization"); got != wantAuth {
				t.Errorf("Authorization %q, want %q", got, wantAuth)
			}
			wantType := ""
			if tc.body != "" {
				wantType = "application/json"
			}
			if got := req.header.Get("Content-Type"); got != wantType {
				t.Errorf("Content-Type %q, want %q", got, wantType)
			}
			if got := req.header.Get("Accept"); got != "application/json" {
				t.Errorf("Accept %q, want application/json", got)
			}
			if got := req.header.Get("User-Agent"); got != "test-app/1.0 rypt-go/dev" {
				t.Errorf("User-Agent %q", got)
			}
		})
	}
}

// TestEndpointRetries checks each method's retry policy: every method is
// retried after 503 unavailable, and only those safe to repeat after a 502
// or a dropped connection.
func TestEndpointRetries(t *testing.T) {
	faults := []struct {
		name      string
		fault     func() responder
		alwaysYes bool // retried whatever the policy
	}{
		{"503 unavailable", func() responder { return apiErr(503, "unavailable", "queue full") }, true},
		{"502 page", func() responder { return rawReply(502, "text/html", "<html>bad gateway</html>") }, false},
		{"504 envelope", func() responder { return apiErr(504, "internal_error", "timeout") }, false},
		{"503 page", func() responder { return rawReply(503, "text/plain", "service unavailable") }, false},
		{"dropped connection", dropConn, false},
	}
	for _, tc := range endpointCases(t) {
		for _, f := range faults {
			t.Run(tc.name+"/"+f.name, func(t *testing.T) {
				api := newFakeAPI(t)
				api.script(f.fault(), tc.responder())
				_, err := tc.call(t.Context(), api.client())
				retried := f.alwaysYes || tc.retry == retryIfTransient
				n := len(api.requests())
				switch {
				case retried && (err != nil || n != 2):
					t.Errorf("err %v after %d requests; want success after 2", err, n)
				case !retried && (err == nil || n != 1):
					t.Errorf("err %v after %d requests; want an error after 1", err, n)
				}
			})
		}
	}
}

// TestInvalidIDs: an id that is not a UUID is refused before any request,
// so that it cannot change which endpoint is reached.
func TestInvalidIDs(t *testing.T) {
	api := newFakeAPI(t)
	c := api.client()
	ctx := t.Context()
	for _, id := range []string{"", "..", "../api-tokens", keyID + "/rotate", keyID[:35], keyID + "0", "0f1e2d3c_4b5a-6978-8796-a5b4c3d2e1f0", "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1fg"} {
		calls := map[string]func() error{
			"GetKey":          func() error { _, err := c.GetKey(ctx, id); return err },
			"DestroyKey":      func() error { return c.DestroyKey(ctx, id) },
			"Encrypt":         func() error { _, err := c.Encrypt(ctx, id, []byte("x"), nil); return err },
			"ListAuditEvents": func() error { _, err := c.ListAuditEvents(ctx, id, nil); return err },
			"UpdateAPIToken":  func() error { _, err := c.UpdateAPIToken(ctx, id, nil); return err },
			"RevokeAPIToken":  func() error { return c.RevokeAPIToken(ctx, id) },
			"DeleteContainer": func() error { return c.DeleteContainer(ctx, id) },
			"UpdateFirewall":  func() error { _, err := c.UpdateFirewall(ctx, id, nil); return err },
		}
		if id != "" { // an empty container id means the default container
			calls["CreateKey"] = func() error {
				_, err := c.CreateKey(ctx, &CreateKeyParams{Name: "k", Tier: TierFree, ContainerID: id})
				return err
			}
		}
		for name, call := range calls {
			err := call()
			if err == nil {
				t.Errorf("%s(%q) succeeded", name, id)
			} else if _, ok := err.(*Error); ok {
				t.Errorf("%s(%q) = %v, want a local error", name, id, err)
			}
		}
	}
	if n := len(api.requests()); n != 0 {
		t.Errorf("sent %d requests", n)
	}
	// Upper-case hex is a UUID too.
	if _, err := c.GetKey(ctx, "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0"); err != nil {
		t.Errorf("upper-case id: %v", err)
	}
}

// TestLocalArgumentErrors: arguments that cannot make a valid request fail
// before any request.
func TestLocalArgumentErrors(t *testing.T) {
	api := newFakeAPI(t)
	c := api.client()
	ctx := t.Context()
	calls := map[string]func() error{
		"Encrypt empty":      func() error { _, err := c.Encrypt(ctx, keyID, nil, []byte("a")); return err },
		"Decrypt empty":      func() error { _, err := c.Decrypt(ctx, keyID, []byte{}, nil); return err },
		"Rewrap empty":       func() error { _, err := c.Rewrap(ctx, keyID, nil, nil); return err },
		"Wrap empty":         func() error { _, err := c.Wrap(ctx, keyID, nil, []byte("a")); return err },
		"Unwrap empty":       func() error { _, err := c.Unwrap(ctx, keyID, nil, nil); return err },
		"CreateKey nil":      func() error { _, err := c.CreateKey(ctx, nil); return err },
		"CreateToken nil":    func() error { _, err := c.CreateAPIToken(ctx, nil); return err },
		"CreateFirewall nil": func() error { _, err := c.CreateFirewall(ctx, nil); return err },
		"negative limit": func() error {
			_, err := c.ListAuditEvents(ctx, keyID, &AuditEventsParams{Limit: -1})
			return err
		},
	}
	for name, call := range calls {
		if err := call(); err == nil {
			t.Errorf("%s succeeded", name)
		}
	}
	if n := len(api.requests()); n != 0 {
		t.Errorf("sent %d requests", n)
	}
}

// TestOptionalParams: nil params and zero fields leave everything out.
func TestOptionalParams(t *testing.T) {
	api := newFakeAPI(t)
	api.fallback = jsonReply(200, []any{})
	c := api.client()
	if _, err := c.ListAuditEvents(t.Context(), keyID, nil); err != nil {
		t.Fatal(err)
	}
	if q := api.last().query; q != "" {
		t.Errorf("query %q, want none", q)
	}
	if _, err := c.Usage(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	if q := api.last().query; q != "" {
		t.Errorf("query %q, want none", q)
	}
	api.fallback = jsonReply(200, map[string]any{"wrapped": b64([]byte("W")), "dek": b64(bytes.Repeat([]byte{1}, 32))})
	if _, err := c.GenerateDataKey(t.Context(), keyID, nil); err != nil {
		t.Fatal(err)
	}
	if b := string(api.last().body); b != "{}" {
		t.Errorf("GenerateDataKey with no aad sent %s, want {}", b)
	}
	api.fallback = jsonReply(200, map[string]any{})
	if _, err := c.UpdateAPIToken(t.Context(), tokenID, nil); err != nil {
		t.Fatal(err)
	}
	if b := string(api.last().body); b != "{}" {
		t.Errorf("UpdateAPIToken with nil params sent %s, want {}", b)
	}
}
