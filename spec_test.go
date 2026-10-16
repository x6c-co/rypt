package rypt

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// These tests hold the client to the OpenAPI description it was written
// against, testdata/openapi.json. When the API changes, replace that file
// with the new description and these tests list what the client is
// missing.

// spec is the decoded OpenAPI description.
type spec struct {
	Paths      map[string]map[string]specOp `json:"paths"`
	Components struct {
		Schemas map[string]*schema `json:"schemas"`
	} `json:"components"`
}

type specOp struct {
	OperationID string `json:"operationId"`
	RequestBody *struct {
		Content map[string]struct {
			Schema *schema `json:"schema"`
		} `json:"content"`
	} `json:"requestBody"`
	Responses map[string]struct {
		Content map[string]struct {
			Schema *schema `json:"schema"`
		} `json:"content"`
	} `json:"responses"`
}

type schema struct {
	Ref        string             `json:"$ref"`
	Type       string             `json:"type"`
	Properties map[string]*schema `json:"properties"`
	Required   []string           `json:"required"`
	Items      *schema            `json:"items"`
	AllOf      []*schema          `json:"allOf"`
	Enum       []string           `json:"enum"`
}

func loadSpec(t *testing.T) *spec {
	t.Helper()
	raw, err := os.ReadFile("testdata/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var s spec
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

// resolve follows $ref and merges allOf into one object schema.
func (s *spec) resolve(t *testing.T, sc *schema) *schema {
	t.Helper()
	if sc == nil {
		t.Fatal("missing schema")
	}
	if sc.Ref != "" {
		name := strings.TrimPrefix(sc.Ref, "#/components/schemas/")
		ref, ok := s.Components.Schemas[name]
		if !ok {
			t.Fatalf("unknown schema %s", sc.Ref)
		}
		return s.resolve(t, ref)
	}
	if len(sc.AllOf) == 0 {
		return sc
	}
	merged := &schema{Type: "object", Properties: map[string]*schema{}}
	for _, part := range sc.AllOf {
		p := s.resolve(t, part)
		for k, v := range p.Properties {
			merged.Properties[k] = v
		}
		merged.Required = append(merged.Required, p.Required...)
	}
	return merged
}

func (s *spec) op(t *testing.T, id string) (method, path string, op specOp) {
	t.Helper()
	for p, ops := range s.Paths {
		for m, o := range ops {
			if o.OperationID == id {
				return strings.ToUpper(m), p, o
			}
		}
	}
	t.Fatalf("no operation %s in the spec", id)
	return "", "", specOp{}
}

// jsonFields returns the JSON field names of a struct type, including those
// of embedded structs, and whether each may be left out.
func jsonFields(typ reflect.Type) map[string]bool {
	fields := map[string]bool{}
	for i := range typ.NumField() {
		f := typ.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			for k, v := range jsonFields(f.Type) {
				fields[k] = v
			}
			continue
		}
		tag := f.Tag.Get("json")
		if !f.IsExported() || tag == "" || tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		fields[name] = strings.Contains(opts, "omitempty") || strings.Contains(opts, "omitzero")
	}
	return fields
}

// compareObject checks that typ has exactly the properties of the object
// schema sc. When it is a request type, it also checks that no required
// property may be left out.
func compareObject(t *testing.T, name string, sc *schema, typ reflect.Type, request bool) {
	t.Helper()
	fields := jsonFields(typ)
	var props []string
	for p := range sc.Properties {
		props = append(props, p)
		if _, ok := fields[p]; !ok {
			t.Errorf("%s: %s has no field for property %q", name, typ, p)
		}
	}
	for f, omittable := range fields {
		if !slices.Contains(props, f) {
			t.Errorf("%s: %s has field %q, which the spec does not", name, typ, f)
		}
		if request && omittable && slices.Contains(sc.Required, f) {
			t.Errorf("%s: %s may leave out required property %q", name, typ, f)
		}
	}
}

// TestSpecOperations: every operation in the spec that a client makes has
// a case in TestEndpoints, which sends it with the spec's method and path
// and gets the spec's success status.
func TestSpecOperations(t *testing.T) {
	s := loadSpec(t)
	byOp := map[string][]endpointCase{}
	for _, tc := range endpointCases(t) {
		byOp[tc.op] = append(byOp[tc.op], tc)
	}
	skip := map[string]string{
		"stripeWebhook": "Stripe calls it, not clients",
		"healthzRoot":   "the same handler as healthzV1, which production serves",
	}
	for path, ops := range s.Paths {
		for method, op := range ops {
			if _, ok := skip[op.OperationID]; ok {
				continue
			}
			cases := byOp[op.OperationID]
			if len(cases) == 0 {
				t.Errorf("%s %s (%s) has no client method", strings.ToUpper(method), path, op.OperationID)
				continue
			}
			for _, tc := range cases {
				wantPath := path
				for _, id := range []string{keyID, containerID, firewallID, tokenID} {
					if strings.Count(tc.path, id) == 1 {
						wantPath = strings.Replace(path, "{id}", id, 1)
					}
				}
				if tc.method != strings.ToUpper(method) || tc.path != wantPath {
					t.Errorf("%s: %s sends %s %s, the spec says %s %s", tc.name, op.OperationID, tc.method, tc.path, strings.ToUpper(method), path)
				}
				status := ""
				for code := range op.Responses {
					if strings.HasPrefix(code, "2") {
						status = code
					}
				}
				if status != "" && status != strconv.Itoa(tc.status) {
					t.Errorf("%s: the case answers %d, the spec %s", tc.name, tc.status, status)
				}
			}
			delete(byOp, op.OperationID)
		}
	}
	for op := range byOp {
		t.Errorf("TestEndpoints has a case for %s, which is not in the spec", op)
	}
}

// TestSpecSchemas: each type the client decodes has exactly the
// properties of its schema.
func TestSpecSchemas(t *testing.T) {
	s := loadSpec(t)
	types := map[string]any{
		"Key":                Key{},
		"RetiringVersion":    RetiringVersion{},
		"CiphertextResponse": ciphertextResponse{},
		"AuditEvent":         AuditEvent{},
		"Me":                 Me{},
		"ApiToken":           APIToken{},
		"UpdatedApiToken":    UpdatedAPIToken{},
		"CreatedApiToken":    CreatedAPIToken{},
		"ChainHead":          ChainHead{},
		"PermissionChain":    PermissionChain{},
		"Container":          Container{},
		"Firewall":           Firewall{},
		"UsageLine":          UsageLine{},
		"Billing":            Billing{},
		"BillingEstimate":    BillingEstimate{},
		"BillingLine":        BillingLine{},
		"BillingSession":     BillingSession{},
		"Health":             healthResponse{},
	}
	for name, sc := range s.Components.Schemas {
		if sc.Type == "array" || name == "Error" {
			continue // AllowedActions is checked as an enum, Error by TestSpecErrorEnvelope
		}
		v, ok := types[name]
		if !ok {
			t.Errorf("schema %s has no Go type", name)
			continue
		}
		compareObject(t, name, s.resolve(t, sc), reflect.TypeOf(v), false)
	}
	me := s.resolve(t, s.Components.Schemas["Me"])
	compareObject(t, "Me.user", me.Properties["user"], reflect.TypeOf(User{}), false)
	compareObject(t, "Me.tenant", me.Properties["tenant"], reflect.TypeOf(Tenant{}), false)

	// Inline response schemas.
	for op, v := range map[string]any{"decrypt": plaintextResponse{}, "wrap": wrapResponse{}, "unwrap": unwrapResponse{}} {
		_, _, o := s.op(t, op)
		compareObject(t, op+" response", s.resolve(t, o.Responses["200"].Content["application/json"].Schema), reflect.TypeOf(v), false)
	}
}

// TestSpecRequestBodies: each request type has exactly the properties of
// its operation's body, and never leaves out a required one.
func TestSpecRequestBodies(t *testing.T) {
	s := loadSpec(t)
	type nameOnly struct {
		Name string `json:"name"`
	}
	for op, v := range map[string]any{
		"createKey":       CreateKeyParams{},
		"renameKey":       nameOnly{},
		"createApiToken":  CreateAPITokenParams{},
		"updateApiToken":  UpdateAPITokenParams{},
		"createContainer": nameOnly{},
		"renameContainer": nameOnly{},
		"createFirewall":  CreateFirewallParams{},
		"updateFirewall":  UpdateFirewallParams{},
	} {
		_, _, o := s.op(t, op)
		compareObject(t, op, s.resolve(t, o.RequestBody.Content["application/json"].Schema), reflect.TypeOf(v), true)
	}

	// The cryptographic bodies are built by hand: send each with every
	// field and compare what arrives.
	for _, tc := range []struct {
		op   string
		call func(*Client) error
	}{
		{"encrypt", func(c *Client) error { _, err := c.Encrypt(t.Context(), keyID, []byte("p"), []byte("a")); return err }},
		{"decrypt", func(c *Client) error { _, err := c.Decrypt(t.Context(), keyID, []byte("c"), []byte("a")); return err }},
		{"rewrap", func(c *Client) error { _, err := c.Rewrap(t.Context(), keyID, []byte("c"), []byte("a")); return err }},
		{"wrap", func(c *Client) error { _, err := c.Wrap(t.Context(), keyID, make([]byte, 32), []byte("a")); return err }},
		{"unwrap", func(c *Client) error { _, err := c.Unwrap(t.Context(), keyID, []byte("w"), []byte("a")); return err }},
	} {
		api := newFakeAPI(t)
		tc.call(api.client())
		var sent map[string]any
		if err := json.Unmarshal(api.last().body, &sent); err != nil {
			t.Fatalf("%s: %v", tc.op, err)
		}
		_, _, o := s.op(t, tc.op)
		sc := s.resolve(t, o.RequestBody.Content["application/json"].Schema)
		var props, fields []string
		for p := range sc.Properties {
			props = append(props, p)
		}
		for f := range sent {
			fields = append(fields, f)
		}
		slices.Sort(props)
		slices.Sort(fields)
		if !slices.Equal(props, fields) {
			t.Errorf("%s sends %v, the spec has %v", tc.op, fields, props)
		}
	}
}

// TestSpecEnums: the constants cover every value of each enum.
func TestSpecEnums(t *testing.T) {
	s := loadSpec(t)
	sc := s.Components.Schemas
	enums := []struct {
		name   string
		schema *schema
		consts []string
	}{
		{"tier", sc["Key"].Properties["tier"], strs(TierFree, TierWrapped, TierSoftware, TierHSM)},
		{"state", sc["Key"].Properties["state"], strs(KeyActive, KeyPendingDeletion)},
		{"actions", sc["AllowedActions"].Items, strs(ActionEncrypt, ActionDecrypt, ActionWrap, ActionUnwrap,
			ActionRewrap, ActionRotate, ActionRename, ActionDelete, ActionRestore, ActionCreate, ActionRead)},
		{"op", sc["AuditEvent"].Properties["op"], strs(OpCreateKey, OpRenameKey, OpDeleteKey, OpRestoreKey,
			OpDestroyKey, OpRotate, OpDestroyVersion, OpEncrypt, OpDecrypt, OpWrap, OpUnwrap, OpRewrap,
			OpCreateAPIToken, OpUpdateAPIToken, OpRevokeAPIToken, OpCreateContainer, OpRenameContainer,
			OpDeleteContainer, OpCreateFirewall, OpUpdateFirewall, OpDeleteFirewall)},
		{"result", sc["AuditEvent"].Properties["result"], strs(ResultOK, ResultError)},
		{"role", sc["Me"].Properties["role"], strs(RoleOwner, RoleAdmin, RoleMember)},
		{"billing status", sc["Billing"].Properties["status"], strs(BillingNone, BillingActive, BillingPastDue, BillingUnpaid, BillingLapsed)},
		{"billing tier", sc["BillingLine"].Properties["tier"], strs(TierWrapped, TierSoftware, TierHSM)},
		{"error code", sc["Error"].Properties["error"], strs(
			CodeInvalidRequest, CodeInvalidBase64, CodeInvalidTier, CodeInvalidName, CodeInvalidDEKLength,
			CodeInvalidCiphertext, CodeInvalidPeriod, CodeInvalidQuery, CodeInvalidAllowedIPs, CodeInvalidKeyIDs,
			CodeInvalidAllowedActions, CodeInvalidContainer, CodeInvalidFirewall, CodeUnauthorized,
			CodeBillingRequired, CodeAPITokenRequired, CodeSessionRequired, CodeIPNotAllowed, CodeKeyNotAllowed,
			CodeActionNotAllowed, CodeNoTenant, CodeNotFound, CodeMethodNotAllowed, CodeKeyExists, CodeFreeKeyExists,
			CodeKeyPendingDeletion, CodeTooManyRetiringVersions, CodeNotPendingDeletion, CodeRestoreWindowClosed,
			CodeContainerExists, CodeFirewallExists, CodeContainerNotEmpty, CodeContainerIsDefault, CodeFirewallInUse,
			CodeBillingActive, CodeBillingNotSetUp, CodePayloadTooLarge, CodeUnsupportedMediaType, CodeOpsCapReached,
			CodeRateLimited, CodeInternalError, CodeUnavailable)},
	}
	for _, e := range enums {
		want := slices.Sorted(slices.Values(e.schema.Enum))
		got := slices.Sorted(slices.Values(e.consts))
		if !slices.Equal(got, want) {
			t.Errorf("%s: constants %v, spec %v", e.name, got, want)
		}
	}
}

// TestSpecErrorEnvelope: the client decodes every field of the error
// envelope.
func TestSpecErrorEnvelope(t *testing.T) {
	s := loadSpec(t)
	var props []string
	for p := range s.Components.Schemas["Error"].Properties {
		props = append(props, p)
	}
	slices.Sort(props)
	decoded := []string{"cap", "error", "message", "request_id", "resets_at"} // see Client.apiError
	if !slices.Equal(props, decoded) {
		t.Errorf("the error envelope has %v; apiError decodes %v", props, decoded)
	}
}

func strs[S ~string](vs ...S) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = string(v)
	}
	return out
}
