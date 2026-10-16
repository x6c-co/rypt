package rypt

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrorKind classifies an [Error].
type ErrorKind int

const (
	// KindAPI means the API answered with an error status. Code holds the
	// API's error code when the body was the API's error envelope.
	KindAPI ErrorKind = iota + 1
	// KindTransport means the API could not be reached, or the connection
	// failed before a complete response arrived. StatusCode is 0.
	KindTransport
	// KindResponse means the API answered with a success status but a body
	// that does not have the documented shape.
	KindResponse
)

// String returns "api", "transport" or "response".
func (k ErrorKind) String() string {
	switch k {
	case KindAPI:
		return "api"
	case KindTransport:
		return "transport"
	case KindResponse:
		return "response"
	}
	return "ErrorKind(" + strconv.Itoa(int(k)) + ")"
}

// Error is the error a call returns when it fails after making a request,
// unless the call's context ended first, in which case the call returns the
// context's error.
//
// All text in an Error that came from the server has had control and
// invisible formatting characters removed, is cut to a few hundred bytes,
// and has any copy of the client's token replaced with "[redacted]".
type Error struct {
	// Kind says what went wrong.
	Kind ErrorKind
	// StatusCode is the HTTP status of the last response, or 0 when no
	// response arrived.
	StatusCode int
	// Code is the API's machine-readable error code, or empty when the
	// response did not carry the API's error envelope, as with an error
	// page from a proxy.
	Code ErrorCode
	// Message is the API's human-readable message, or a description of the
	// failure when the API did not send one.
	Message string
	// RequestID identifies the last request in the API's logs. It is the
	// error body's request_id, or else the x-request-id response header.
	RequestID string
	// Cap is the key tier's monthly operation cap, for CodeOpsCapReached.
	Cap int64
	// ResetsAt is when the monthly operation counter resets, for
	// CodeOpsCapReached.
	ResetsAt time.Time
	// Attempts is how many requests were sent.
	Attempts int
	// Err is the underlying error of a KindTransport error.
	Err error
}

// Error returns a one-line description that includes the API's error code,
// message and request id when there are any.
func (e *Error) Error() string {
	var b strings.Builder
	switch e.Kind {
	case KindTransport:
		msg := e.Message
		if msg == "" {
			msg = "cannot reach the rypt API"
		}
		b.WriteString(msg)
		switch {
		case e.Attempts == 1:
			b.WriteString(" after 1 attempt")
		case e.Attempts > 1:
			fmt.Fprintf(&b, " after %d attempts", e.Attempts)
		}
		if e.Err != nil {
			b.WriteString(": ")
			b.WriteString(e.Err.Error())
		}
		return b.String()
	case KindResponse:
		fmt.Fprintf(&b, "malformed rypt API response (HTTP %d)", e.StatusCode)
		if e.Message != "" {
			b.WriteString(": ")
			b.WriteString(e.Message)
		}
	default:
		b.WriteString("rypt API error")
		if e.Code != "" {
			b.WriteString(" ")
			b.WriteString(string(e.Code))
		}
		fmt.Fprintf(&b, " (HTTP %d)", e.StatusCode)
		if e.Message != "" {
			b.WriteString(": ")
			b.WriteString(e.Message)
		}
		var limits []string
		if e.Cap > 0 {
			limits = append(limits, "cap "+strconv.FormatInt(e.Cap, 10))
		}
		if !e.ResetsAt.IsZero() {
			limits = append(limits, "resets at "+e.ResetsAt.Format(time.RFC3339))
		}
		if len(limits) > 0 {
			b.WriteString("; ")
			b.WriteString(strings.Join(limits, ", "))
		}
	}
	if e.RequestID != "" {
		fmt.Fprintf(&b, " (request_id %s)", e.RequestID)
	}
	return b.String()
}

// Unwrap returns e.Err.
func (e *Error) Unwrap() error { return e.Err }

// IsCode reports whether err is, or wraps, an [*Error] whose Code is code.
func IsCode(err error, code ErrorCode) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// ErrorCode is one of the API's stable, machine-readable error codes.
type ErrorCode string

// The API's error codes, by HTTP status.
const (
	// 400 Bad Request.

	CodeInvalidRequest        ErrorCode = "invalid_request"         // the body or a parameter is malformed, or names an unknown field
	CodeInvalidBase64         ErrorCode = "invalid_base64"          // a binary field is not standard padded base64
	CodeInvalidTier           ErrorCode = "invalid_tier"            // the tier is not one of the four
	CodeInvalidName           ErrorCode = "invalid_name"            // a name is empty, too long, only whitespace, or has control characters
	CodeInvalidDEKLength      ErrorCode = "invalid_dek_length"      // a data key to wrap is not 16, 24 or 32 bytes
	CodeInvalidCiphertext     ErrorCode = "invalid_ciphertext"      // the ciphertext was refused, the aad does not match, or its version is gone
	CodeInvalidPeriod         ErrorCode = "invalid_period"          // a usage period is not YYYY-MM
	CodeInvalidQuery          ErrorCode = "invalid_query"           // a query parameter is invalid
	CodeInvalidAllowedIPs     ErrorCode = "invalid_allowed_ips"     // a firewall network is invalid
	CodeInvalidKeyIDs         ErrorCode = "invalid_key_ids"         // a key list is empty or names a key outside the container
	CodeInvalidAllowedActions ErrorCode = "invalid_allowed_actions" // an action list is null or names an unknown action
	CodeInvalidContainer      ErrorCode = "invalid_container"       // the container is not one the caller may use
	CodeInvalidFirewall       ErrorCode = "invalid_firewall"        // the firewall is not a live one of the container

	// 401 Unauthorized.

	CodeUnauthorized ErrorCode = "unauthorized" // the token is missing, malformed, unknown, revoked or wrong

	// 402 Payment Required.

	CodeBillingRequired ErrorCode = "billing_required" // the tenant's billing is not in good standing

	// 403 Forbidden.

	CodeAPITokenRequired ErrorCode = "api_token_required" // the endpoint needs an API token, not a console session
	CodeSessionRequired  ErrorCode = "session_required"   // the endpoint needs a console session, not an API token
	CodeIPNotAllowed     ErrorCode = "ip_not_allowed"     // the API token was used from outside its firewall's networks
	CodeKeyNotAllowed    ErrorCode = "key_not_allowed"    // the API token is restricted to other keys
	CodeActionNotAllowed ErrorCode = "action_not_allowed" // the API token was not given this action
	CodeNoTenant         ErrorCode = "no_tenant"          // the user belongs to no tenant

	// 404 Not Found and 405 Method Not Allowed.

	CodeNotFound         ErrorCode = "not_found"          // the route or id is unknown, destroyed, or not the caller's to see
	CodeMethodNotAllowed ErrorCode = "method_not_allowed" // the route does not take this method

	// 409 Conflict.

	CodeKeyExists               ErrorCode = "key_exists"                 // another live key in the container has the name
	CodeFreeKeyExists           ErrorCode = "free_key_exists"            // the tenant already has its one free key
	CodeKeyPendingDeletion      ErrorCode = "key_pending_deletion"       // the key is pending deletion and refuses every operation
	CodeTooManyRetiringVersions ErrorCode = "too_many_retiring_versions" // the key already has ten versions retiring
	CodeNotPendingDeletion      ErrorCode = "not_pending_deletion"       // the key to restore is not pending deletion
	CodeRestoreWindowClosed     ErrorCode = "restore_window_closed"      // the key is being destroyed and can no longer be restored
	CodeContainerExists         ErrorCode = "container_exists"           // another live container has the name
	CodeFirewallExists          ErrorCode = "firewall_exists"            // another live firewall in the container has the name
	CodeContainerNotEmpty       ErrorCode = "container_not_empty"        // the container still holds keys, API tokens or firewalls
	CodeContainerIsDefault      ErrorCode = "container_is_default"       // the default container cannot be deleted
	CodeFirewallInUse           ErrorCode = "firewall_in_use"            // live API tokens are held to the firewall
	CodeBillingActive           ErrorCode = "billing_active"             // the tenant already has an open subscription
	CodeBillingNotSetUp         ErrorCode = "billing_not_set_up"         // the tenant has never started a checkout

	// 413 Payload Too Large and 415 Unsupported Media Type.

	CodePayloadTooLarge      ErrorCode = "payload_too_large"      // the body or a field is over its limit
	CodeUnsupportedMediaType ErrorCode = "unsupported_media_type" // the body is not sent as application/json

	// 429 Too Many Requests.

	CodeOpsCapReached ErrorCode = "ops_cap_reached" // a free key is at its monthly cap; see Error.Cap and Error.ResetsAt
	CodeRateLimited   ErrorCode = "rate_limited"    // over 100 requests per second for this API token

	// 500 Internal Server Error and 503 Service Unavailable.

	CodeInternalError ErrorCode = "internal_error" // the service failed; the cause is logged with the request id
	CodeUnavailable   ErrorCode = "unavailable"    // the service did not carry out the request; it is safe to retry
)
