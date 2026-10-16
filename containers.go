package rypt

import (
	"context"
	"net/http"
	"time"
)

// Container holds keys, API tokens and firewalls. An API token never sees
// outside its own container. Every tenant has one default container.
type Container struct {
	// ID is the container's id.
	ID string `json:"id"`
	// Name is unique among the tenant's live containers.
	Name string `json:"name"`
	// IsDefault reports whether this is the tenant's default container,
	// which everything goes in unless told otherwise and which cannot be
	// deleted.
	IsDefault bool `json:"is_default"`
	// CreatedAt is when it was created.
	CreatedAt time.Time `json:"created_at"`
}

// PermissionChain is the head of a container's permission chain. See
// [ChainHead].
type PermissionChain struct {
	// ContainerID is the container whose chain this is.
	ContainerID string `json:"container_id"`
	// Head is the chain's latest entry.
	Head ChainHead `json:"head"`
}

// ListContainers returns the tenant's live containers, the default first
// and the rest oldest first. It needs a console session.
func (c *Client) ListContainers(ctx context.Context) ([]Container, error) {
	var containers []Container
	req := &request{method: http.MethodGet, path: "/v1/containers", retry: retryIfTransient}
	if err := c.do(ctx, req, &containers); err != nil {
		return nil, err
	}
	return containers, nil
}

// CreateContainer makes an empty container. Its name follows the rules of
// a key's name and is unique among the tenant's live containers, or the
// call fails with [CodeContainerExists]. It needs a console session.
//
// CreateContainer is not retried once the request may have reached the
// API.
func (c *Client) CreateContainer(ctx context.Context, name string) (*Container, error) {
	body, err := jsonBody(struct {
		Name string `json:"name"`
	}{name})
	if err != nil {
		return nil, err
	}
	var container Container
	req := &request{method: http.MethodPost, path: "/v1/containers", body: body, retry: retryIfUnprocessed}
	if err := c.do(ctx, req, &container); err != nil {
		return nil, err
	}
	return &container, nil
}

// RenameContainer renames a container, the default one included, and
// returns it. A name another live container has fails with
// [CodeContainerExists]. It needs a console session.
//
// Renaming a container to the name it has changes nothing, so
// RenameContainer is retried like a read.
func (c *Client) RenameContainer(ctx context.Context, containerID, name string) (*Container, error) {
	path, err := idPath("containers", "container ID", containerID, "")
	if err != nil {
		return nil, err
	}
	body, err := jsonBody(struct {
		Name string `json:"name"`
	}{name})
	if err != nil {
		return nil, err
	}
	var container Container
	req := &request{method: http.MethodPatch, path: path, body: body, retry: retryIfTransient}
	if err := c.do(ctx, req, &container); err != nil {
		return nil, err
	}
	return &container, nil
}

// DeleteContainer deletes an empty container that is not the default. A
// container that still holds a key, even one pending deletion, a live API
// token or a firewall fails with [CodeContainerNotEmpty]. It needs a
// console session.
//
// DeleteContainer is not retried once the request may have reached the
// API: a second attempt would fail with [CodeNotFound].
func (c *Client) DeleteContainer(ctx context.Context, containerID string) error {
	path, err := idPath("containers", "container ID", containerID, "")
	if err != nil {
		return err
	}
	return c.do(ctx, &request{method: http.MethodDelete, path: path, retry: retryIfUnprocessed}, nil)
}

// PermissionChain returns the head of a container's permission chain. The
// first read of a container's head may start its chain. It needs a console
// session.
func (c *Client) PermissionChain(ctx context.Context, containerID string) (*PermissionChain, error) {
	path, err := idPath("containers", "container ID", containerID, "/permission-chain")
	if err != nil {
		return nil, err
	}
	var chain PermissionChain
	req := &request{method: http.MethodGet, path: path, retry: retryIfTransient}
	if err := c.do(ctx, req, &chain); err != nil {
		return nil, err
	}
	return &chain, nil
}
