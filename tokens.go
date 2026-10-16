package rypt

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Action is something an API token may do with the keys it may act on.
type Action string

// The actions an API token can be given.
const (
	ActionEncrypt Action = "encrypt"
	ActionDecrypt Action = "decrypt"
	ActionWrap    Action = "wrap" // also needed by GenerateDataKey
	ActionUnwrap  Action = "unwrap"
	ActionRewrap  Action = "rewrap"
	ActionRotate  Action = "rotate"
	ActionRename  Action = "rename"
	ActionDelete  Action = "delete"
	ActionRestore Action = "restore"
	// ActionCreate allows creating a key in the token's container. It
	// works only for a token not restricted to particular keys.
	ActionCreate Action = "create"
	// ActionRead allows listing keys, reading a key and its audit log, and
	// reading usage.
	ActionRead Action = "read"
)

// ChainHead is the latest entry of a container's permission chain. Every
// change to what a container's API tokens may do is appended to the chain,
// and each entry includes the hash of the one before it, so the head's hash
// stands for the whole history. Kept somewhere the service cannot reach, it
// is what a rewritten history would fail to match.
type ChainHead struct {
	// Seq is the entry's position; 0 is the chain's first entry.
	Seq int64 `json:"seq"`
	// Hash is the entry's SHA-256 hash, 64 lowercase hex digits.
	Hash string `json:"hash"`
}

// APIToken is an API token, without its secret.
type APIToken struct {
	// ID is the token's id.
	ID string `json:"id"`
	// Name is the label it was created with, or empty for a token made
	// with the rypt-admin tool.
	Name string `json:"name"`
	// CreatedByUserID is the console user who created it, or empty.
	CreatedByUserID string `json:"created_by_user_id"`
	// CreatedAt is when it was created.
	CreatedAt time.Time `json:"created_at"`
	// RevokedAt is when it was revoked, or nil while it is live.
	RevokedAt *time.Time `json:"revoked_at"`
	// ContainerID is the container it lives in and never sees outside of.
	ContainerID string `json:"container_id"`
	// FirewallID is the firewall it is held to, or empty for none.
	FirewallID string `json:"firewall_id"`
	// KeyIDs are the keys of its container it may act on, ascending, or
	// nil when it may act on all of them. A key destroyed since it was
	// named stays in the list.
	KeyIDs []string `json:"key_ids"`
	// AllowedActions is what it may do with those keys, sorted.
	AllowedActions []Action `json:"allowed_actions"`
}

// CreatedAPIToken is an API token just created, with its secret.
type CreatedAPIToken struct {
	// ID is the token's id.
	ID string `json:"id"`
	// Name is the label it was created with.
	Name string `json:"name"`
	// ContainerID is the container it lives in.
	ContainerID string `json:"container_id"`
	// Prefix is the token's 8-character lookup prefix, which is part of
	// Token. It is returned here and nowhere else.
	Prefix string `json:"prefix"`
	// CreatedAt is when it was created.
	CreatedAt time.Time `json:"created_at"`
	// AllowedActions is what it may do, sorted.
	AllowedActions []Action `json:"allowed_actions"`
	// PermissionChainHead is the head of its container's permission chain
	// after the creation was appended to it.
	PermissionChainHead ChainHead `json:"permission_chain_head"`
	// Token is the API token itself, to pass to [NewClient]. It is
	// returned exactly once and cannot be recovered: store it now.
	Token string `json:"token"`
}

// UpdatedAPIToken is an API token as an update left it.
type UpdatedAPIToken struct {
	APIToken
	// PermissionChainHead is the head of the token's container's
	// permission chain after the update, whether or not it moved.
	PermissionChainHead ChainHead `json:"permission_chain_head"`
}

// CreateAPITokenParams are the parameters of [Client.CreateAPIToken].
type CreateAPITokenParams struct {
	// Name is a label that tells the token apart from the tenant's others:
	// 1 to 128 characters, not only whitespace, with no control
	// characters. Required.
	Name string `json:"name"`
	// ContainerID is the container the token lives in, for good. Empty
	// means the tenant's default container.
	ContainerID string `json:"container_id,omitempty"`
	// AllowedActions is what the token may do with its container's keys.
	// Empty allows nothing.
	AllowedActions []Action `json:"allowed_actions,omitempty"`
}

// UpdateAPITokenParams are the parameters of [Client.UpdateAPIToken]. A
// field left as its zero value is not changed.
type UpdateAPITokenParams struct {
	// FirewallID holds the token to a live firewall of its container, or
	// with Clear lifts its firewall.
	FirewallID Patch[string] `json:"firewall_id,omitzero"`
	// KeyIDs restricts the token to 1 to 100 live keys of its container,
	// or with Clear lets it act on every key of its container. An empty
	// list fails with [CodeInvalidKeyIDs]: revoke the token instead.
	KeyIDs Patch[[]string] `json:"key_ids,omitzero"`
	// AllowedActions replaces what the token may do; an empty list allows
	// nothing. It cannot be cleared: Clear fails with
	// [CodeInvalidAllowedActions].
	AllowedActions Patch[[]Action] `json:"allowed_actions,omitzero"`
}

// CreateAPIToken issues an API token and returns it with its secret, which
// is shown only this once. Its creation is appended to its container's
// permission chain. It needs a console session: a token that could issue
// its successor would outlive its own revocation.
//
// CreateAPIToken is not retried once the request may have reached the API,
// since a second token could be issued whose secret nobody sees.
func (c *Client) CreateAPIToken(ctx context.Context, params *CreateAPITokenParams) (*CreatedAPIToken, error) {
	if params == nil {
		return nil, errors.New("rypt: CreateAPIToken needs params")
	}
	if params.ContainerID != "" && !isUUID(params.ContainerID) {
		return nil, errors.New("rypt: the container ID is not a UUID")
	}
	body, err := jsonBody(params)
	if err != nil {
		return nil, err
	}
	var token CreatedAPIToken
	req := &request{method: http.MethodPost, path: "/v1/api-tokens", body: body, retry: retryIfUnprocessed}
	if err := c.do(ctx, req, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

// ListAPITokens returns every API token of the tenant, newest first,
// including revoked ones. Neither a token's secret nor its prefix is ever
// returned. It needs a console session.
func (c *Client) ListAPITokens(ctx context.Context) ([]APIToken, error) {
	var tokens []APIToken
	req := &request{method: http.MethodGet, path: "/v1/api-tokens", retry: retryIfTransient}
	if err := c.do(ctx, req, &tokens); err != nil {
		return nil, err
	}
	return tokens, nil
}

// UpdateAPIToken changes what an API token may do: the firewall it is held
// to, the keys it may act on, and its actions. The change applies from the
// token's next request. A change to its keys or actions is appended to its
// container's permission chain. It needs a console session.
//
// The update sets the token's state rather than changing it step by step,
// so UpdateAPIToken is retried like a read.
func (c *Client) UpdateAPIToken(ctx context.Context, tokenID string, params *UpdateAPITokenParams) (*UpdatedAPIToken, error) {
	path, err := idPath("api-tokens", "API token ID", tokenID, "")
	if err != nil {
		return nil, err
	}
	if params == nil {
		params = &UpdateAPITokenParams{}
	}
	body, err := jsonBody(params)
	if err != nil {
		return nil, err
	}
	var token UpdatedAPIToken
	req := &request{method: http.MethodPatch, path: path, body: body, retry: retryIfTransient}
	if err := c.do(ctx, req, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

// RevokeAPIToken revokes an API token. It stops working from its next
// request. Revoking a token that is already revoked succeeds. It needs a
// console session.
//
// RevokeAPIToken is retried like a read.
func (c *Client) RevokeAPIToken(ctx context.Context, tokenID string) error {
	path, err := idPath("api-tokens", "API token ID", tokenID, "")
	if err != nil {
		return err
	}
	return c.do(ctx, &request{method: http.MethodDelete, path: path, retry: retryIfTransient}, nil)
}
