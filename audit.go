package rypt

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// AuditOp is the operation an [AuditEvent] records.
type AuditOp string

// The operations a key's audit log records.
const (
	OpCreateKey      AuditOp = "create_key"
	OpRenameKey      AuditOp = "rename_key"
	OpDeleteKey      AuditOp = "delete_key"  // deletion requested: the key became pending deletion
	OpRestoreKey     AuditOp = "restore_key" // the key was taken out of pending deletion
	OpDestroyKey     AuditOp = "destroy_key" // the key was destroyed, at once or when its pending deletion ran out
	OpRotate         AuditOp = "rotate"
	OpDestroyVersion AuditOp = "destroy_version" // a retired version was destroyed; see AuditEvent.KMSVersion
	OpEncrypt        AuditOp = "encrypt"
	OpDecrypt        AuditOp = "decrypt"
	OpWrap           AuditOp = "wrap"
	OpUnwrap         AuditOp = "unwrap"
	OpRewrap         AuditOp = "rewrap"
)

// The operations recorded with no key, which a key's audit log never
// returns. They are listed so that every value of the API's op enum has a
// name.
const (
	OpCreateAPIToken  AuditOp = "create_api_token"
	OpUpdateAPIToken  AuditOp = "update_api_token"
	OpRevokeAPIToken  AuditOp = "revoke_api_token"
	OpCreateContainer AuditOp = "create_container"
	OpRenameContainer AuditOp = "rename_container"
	OpDeleteContainer AuditOp = "delete_container"
	OpCreateFirewall  AuditOp = "create_firewall"
	OpUpdateFirewall  AuditOp = "update_firewall"
	OpDeleteFirewall  AuditOp = "delete_firewall"
)

// AuditResult is whether an audited operation succeeded.
type AuditResult string

// The audit results.
const (
	ResultOK    AuditResult = "ok"
	ResultError AuditResult = "error"
)

// AuditEvent is one entry of a key's audit log: an operation that changed
// the key or used its material, successful or not.
//
// An event caused by a request names exactly one of APITokenID and UserID.
// Older events, and those the service records on its own, such as the
// destruction of a key whose pending deletion ran out, name neither.
type AuditEvent struct {
	// ID is the event's id, which increases with time.
	ID int64 `json:"id"`
	// Time is when the operation happened, to the microsecond.
	Time time.Time `json:"ts"`
	// KeyID is the key the operation was on.
	KeyID string `json:"key_id"`
	// APITokenID is the API token the request presented, or empty.
	APITokenID string `json:"api_token_id"`
	// UserID is the console user the request authenticated as, or empty.
	UserID string `json:"user_id"`
	// Op is the operation.
	Op AuditOp `json:"op"`
	// KMSVersion is the short id of the key version the operation used, or
	// empty. For decrypt and unwrap it is set only when the ciphertext
	// named the primary version; for destroy_version it is the version
	// destroyed.
	KMSVersion string `json:"kms_version"`
	// Result is whether the operation succeeded.
	Result AuditResult `json:"result"`
	// ErrorCode is the error code of a failed operation, or empty.
	ErrorCode ErrorCode `json:"error_code"`
	// RequestID is the x-request-id of the request that caused the event,
	// or an id the service made for an event it recorded on its own.
	RequestID string `json:"request_id"`
	// SourceIP is the address the request came from, or empty for an
	// event no request caused.
	SourceIP string `json:"src_ip"`
	// Bytes is the size of the operation's input in bytes, never its
	// content, or nil when the request failed before its input was
	// decoded.
	Bytes *int64 `json:"bytes"`
	// KMSMicros is how long the key-management backend took, in
	// microseconds, or nil for an operation that did not call it.
	KMSMicros *int64 `json:"kms_us"`
}

// AuditEventsParams are the parameters of [Client.ListAuditEvents]. Every
// field is optional.
type AuditEventsParams struct {
	// Since is the oldest time to include, inclusive. Zero means no bound.
	Since time.Time
	// Until is the time to stop before, exclusive. Zero means no bound.
	Until time.Time
	// Limit is how many events to return, 1 to 1000. Zero means 100.
	Limit int
}

// ListAuditEvents returns a key's audit events, newest first. It works for
// keys pending deletion and for destroyed keys. params may be nil.
//
// Since and Until select a window rather than acting as a cursor, so choose
// a Limit that covers the window you ask for. An event's Time round-trips
// exactly as a bound.
//
// An API token needs the read action. Reading the log is not metered and
// does not add to it.
func (c *Client) ListAuditEvents(ctx context.Context, keyID string, params *AuditEventsParams) ([]AuditEvent, error) {
	path, err := idPath("keys", "key ID", keyID, "/audit")
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	if params != nil {
		if !params.Since.IsZero() {
			query.Set("since", params.Since.UTC().Format(time.RFC3339Nano))
		}
		if !params.Until.IsZero() {
			query.Set("until", params.Until.UTC().Format(time.RFC3339Nano))
		}
		if params.Limit < 0 {
			return nil, errors.New("rypt: the audit event limit is negative")
		}
		if params.Limit > 0 {
			query.Set("limit", strconv.Itoa(params.Limit))
		}
	}
	var events []AuditEvent
	req := &request{method: http.MethodGet, path: path, query: query, retry: retryIfTransient}
	if err := c.do(ctx, req, &events); err != nil {
		return nil, err
	}
	return events, nil
}
