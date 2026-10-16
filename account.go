package rypt

import (
	"context"
	"net/http"
	"time"
)

// Role is a user's role in a tenant.
type Role string

// The roles.
const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

// Me is the signed-in console user and the tenant they act as.
type Me struct {
	// User is the signed-in user.
	User User `json:"user"`
	// Tenant is the tenant every other call is scoped to.
	Tenant Tenant `json:"tenant"`
	// Role is the user's role in that tenant.
	Role Role `json:"role"`
}

// User is a console user.
type User struct {
	// ID is the user's id, which audit events record as UserID.
	ID string `json:"id"`
	// Email is the email the access token last carried, or empty. Auth0
	// puts none in an access token by default.
	Email string `json:"email"`
	// Name is the name the access token last carried, or empty.
	Name string `json:"name"`
	// CreatedAt is when the user first authenticated.
	CreatedAt time.Time `json:"created_at"`
}

// Tenant is a rypt tenant.
type Tenant struct {
	// ID is the tenant's id.
	ID string `json:"id"`
	// Name is the tenant's name.
	Name string `json:"name"`
}

// Me returns the console session's user, tenant and role. The first call
// for a user the service has not seen provisions the user and a tenant they
// own. It needs a console session.
func (c *Client) Me(ctx context.Context) (*Me, error) {
	var me Me
	req := &request{method: http.MethodGet, path: "/v1/me", retry: retryIfTransient}
	if err := c.do(ctx, req, &me); err != nil {
		return nil, err
	}
	return &me, nil
}

// Health checks that the API is up and serving. It sends no token, and
// returns nil when the API answers that it is.
func (c *Client) Health(ctx context.Context) error {
	var res healthResponse
	req := &request{method: http.MethodGet, path: "/v1/healthz", retry: retryIfTransient, noAuth: true}
	return c.do(ctx, req, &res)
}

// healthResponse is the body of the health check.
type healthResponse struct {
	Status string `json:"status"`
}

func (r *healthResponse) problem() string {
	if r.Status != "ok" {
		return `status is not "ok"`
	}
	return ""
}
