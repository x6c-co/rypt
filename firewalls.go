package rypt

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Firewall is a named list of networks that API tokens of its container
// can be held to. A token used from outside its firewall's networks fails
// with [CodeIPNotAllowed].
type Firewall struct {
	// ID is the firewall's id.
	ID string `json:"id"`
	// ContainerID is the container it lives in. Only that container's API
	// tokens can be held to it.
	ContainerID string `json:"container_id"`
	// Name is unique among its container's live firewalls.
	Name string `json:"name"`
	// AllowedIPs are networks in CIDR notation, ascending. An address
	// given alone is stored as a /32 or /128 network.
	AllowedIPs []string `json:"allowed_ips"`
	// CreatedAt is when it was created.
	CreatedAt time.Time `json:"created_at"`
}

// CreateFirewallParams are the parameters of [Client.CreateFirewall].
type CreateFirewallParams struct {
	// ContainerID is the container it goes in. Empty means the tenant's
	// default container.
	ContainerID string `json:"container_id,omitempty"`
	// Name follows the rules of a key's name and is unique among its
	// container's live firewalls. Required.
	Name string `json:"name"`
	// AllowedIPs are 1 to 64 addresses or networks in CIDR notation.
	// "0.0.0.0/0" and "::/0" allow a whole address family. A network with
	// bits set past its prefix, such as "203.0.113.5/24", an IPv4 address
	// written as IPv6, and surrounding whitespace fail with
	// [CodeInvalidAllowedIPs]. Required.
	AllowedIPs []string `json:"allowed_ips"`
}

// UpdateFirewallParams are the parameters of [Client.UpdateFirewall]. A
// field left as its zero value is not changed.
type UpdateFirewallParams struct {
	// Name is the firewall's new name.
	Name string `json:"name,omitempty"`
	// AllowedIPs replaces the firewall's networks, checked as in
	// [CreateFirewallParams]. An empty list is left out of the request.
	AllowedIPs []string `json:"allowed_ips,omitempty"`
}

// ListFirewalls returns the tenant's live firewalls in every container,
// oldest first. It needs a console session.
func (c *Client) ListFirewalls(ctx context.Context) ([]Firewall, error) {
	var firewalls []Firewall
	req := &request{method: http.MethodGet, path: "/v1/firewalls", retry: retryIfTransient}
	if err := c.do(ctx, req, &firewalls); err != nil {
		return nil, err
	}
	return firewalls, nil
}

// CreateFirewall makes a firewall. Hold API tokens of its container to it
// with [Client.UpdateAPIToken]. It needs a console session.
//
// CreateFirewall is not retried once the request may have reached the API.
func (c *Client) CreateFirewall(ctx context.Context, params *CreateFirewallParams) (*Firewall, error) {
	if params == nil {
		return nil, errors.New("rypt: CreateFirewall needs params")
	}
	if params.ContainerID != "" && !isUUID(params.ContainerID) {
		return nil, errors.New("rypt: the container ID is not a UUID")
	}
	body, err := jsonBody(params)
	if err != nil {
		return nil, err
	}
	var firewall Firewall
	req := &request{method: http.MethodPost, path: "/v1/firewalls", body: body, retry: retryIfUnprocessed}
	if err := c.do(ctx, req, &firewall); err != nil {
		return nil, err
	}
	return &firewall, nil
}

// UpdateFirewall renames a firewall, replaces its networks, or both, and
// returns it. New networks apply to every API token held to it from the
// token's next request. It needs a console session.
//
// The update sets the firewall's state rather than changing it step by
// step, so UpdateFirewall is retried like a read.
func (c *Client) UpdateFirewall(ctx context.Context, firewallID string, params *UpdateFirewallParams) (*Firewall, error) {
	path, err := idPath("firewalls", "firewall ID", firewallID, "")
	if err != nil {
		return nil, err
	}
	if params == nil {
		params = &UpdateFirewallParams{}
	}
	body, err := jsonBody(params)
	if err != nil {
		return nil, err
	}
	var firewall Firewall
	req := &request{method: http.MethodPatch, path: path, body: body, retry: retryIfTransient}
	if err := c.do(ctx, req, &firewall); err != nil {
		return nil, err
	}
	return &firewall, nil
}

// DeleteFirewall deletes a firewall. One that a live API token is held to
// fails with [CodeFirewallInUse]: lift it from each token with
// [Client.UpdateAPIToken] first. It needs a console session.
//
// DeleteFirewall is not retried once the request may have reached the API:
// a second attempt would fail with [CodeNotFound].
func (c *Client) DeleteFirewall(ctx context.Context, firewallID string) error {
	path, err := idPath("firewalls", "firewall ID", firewallID, "")
	if err != nil {
		return err
	}
	return c.do(ctx, &request{method: http.MethodDelete, path: path, retry: retryIfUnprocessed}, nil)
}
