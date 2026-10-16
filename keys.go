package rypt

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Tier is a key's tier. It decides the Cloud KMS protection level, how many
// versions a rotation keeps, how many operations a month are included, and
// the price. A key's tier is fixed when it is created.
type Tier string

// The four tiers.
const (
	// TierFree is a wrapped key with a hard monthly cap of 10,000
	// operations. A tenant may hold one live free key.
	TierFree Tier = "free"
	// TierWrapped is the free tier's backend without its cap: a rypt data
	// key wrapped by a shared Cloud KMS root. Paid.
	TierWrapped Tier = "wrapped"
	// TierSoftware is a Cloud KMS key at SOFTWARE protection level. Paid.
	TierSoftware Tier = "software"
	// TierHSM is a Cloud KMS key at HSM protection level. Paid. Its
	// plaintext (or data key) and aad may total at most 8,176 bytes.
	TierHSM Tier = "hsm"
)

// KeyState is whether a key is usable.
type KeyState string

// The key states.
const (
	// KeyActive is a key that can be used.
	KeyActive KeyState = "active"
	// KeyPendingDeletion is a key that was deleted and is not yet
	// destroyed. It refuses every operation with [CodeKeyPendingDeletion]
	// until it is restored with [Client.RestoreKey].
	KeyPendingDeletion KeyState = "pending_deletion"
)

// Key is a rypt key.
type Key struct {
	// ID is the key's id, which every key operation takes.
	ID string `json:"id"`
	// ContainerID is the container the key lives in, fixed at creation.
	ContainerID string `json:"container_id"`
	// Name is unique among its container's live keys.
	Name string `json:"name"`
	// Tier is fixed at creation.
	Tier Tier `json:"tier"`
	// Versions are the short ids of the key's enabled versions, ascending.
	Versions []string `json:"versions"`
	// PrimaryVersion is the version new ciphertext is made under. It is
	// always one of Versions.
	PrimaryVersion string `json:"primary_version"`
	// RetiringVersions are the versions a rotation retired, ascending,
	// each with the time it is destroyed. Each is also in Versions.
	RetiringVersions []RetiringVersion `json:"retiring_versions"`
	// CreatedAt is when the key was created.
	CreatedAt time.Time `json:"created_at"`
	// State is whether the key is active or pending deletion.
	State KeyState `json:"state"`
	// DeleteRequestedAt is when deletion was requested, or nil unless the
	// key is pending deletion.
	DeleteRequestedAt *time.Time `json:"delete_requested_at"`
	// DestroyAfter is when a key pending deletion is destroyed unless it
	// is restored first, seven days after DeleteRequestedAt, or nil unless
	// the key is pending deletion. From this time on it can no longer be
	// restored, though it may be listed for a while longer.
	DestroyAfter *time.Time `json:"destroy_after"`
}

// RetiringVersion is a key version that a rotation retired. Until
// DestroyAfter it still decrypts, unwraps and rewraps; after that, anything
// still under it can never be decrypted again.
type RetiringVersion struct {
	// Version is the version's short id.
	Version string `json:"version"`
	// DestroyAfter is when the version is destroyed, seven days after the
	// rotation that retired it.
	DestroyAfter time.Time `json:"destroy_after"`
}

// CreateKeyParams are the parameters of [Client.CreateKey].
type CreateKeyParams struct {
	// Name is 1 to 128 characters, not only whitespace, with no control
	// characters, and unique among the container's live keys, including
	// those pending deletion. Required.
	Name string `json:"name"`
	// Tier is the key's tier. Required.
	Tier Tier `json:"tier"`
	// ContainerID is the container the key goes in. Empty means the API
	// token's own container, or the tenant's default container for a
	// console session. An API token cannot name another container.
	ContainerID string `json:"container_id,omitempty"`
}

// CreateKey creates a key.
//
// With an API token, the token needs the create action and must not be
// restricted to particular keys. Where billing is configured, a paid tier
// needs the tenant's billing in good standing, or the call fails with
// [CodeBillingRequired], and a second free key fails with
// [CodeFreeKeyExists]. A name in use fails with [CodeKeyExists].
//
// CreateKey is not retried once the request may have reached the API.
func (c *Client) CreateKey(ctx context.Context, params *CreateKeyParams) (*Key, error) {
	if params == nil {
		return nil, errors.New("rypt: CreateKey needs params")
	}
	if params.ContainerID != "" && !isUUID(params.ContainerID) {
		return nil, errors.New("rypt: the container ID is not a UUID")
	}
	body, err := jsonBody(params)
	if err != nil {
		return nil, err
	}
	var key Key
	req := &request{method: http.MethodPost, path: "/v1/keys", body: body, retry: retryIfUnprocessed}
	if err := c.do(ctx, req, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

// ListKeys returns the keys the caller may see, oldest first, including
// those pending deletion: for a console session the whole tenant's, for an
// API token its container's, and for one restricted to particular keys only
// those. An API token needs the read action. It is not metered.
func (c *Client) ListKeys(ctx context.Context) ([]Key, error) {
	var keys []Key
	req := &request{method: http.MethodGet, path: "/v1/keys", retry: retryIfTransient}
	if err := c.do(ctx, req, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

// GetKey returns a key, including one pending deletion. A destroyed key
// fails with [CodeNotFound]. An API token needs the read action. It is not
// metered.
func (c *Client) GetKey(ctx context.Context, keyID string) (*Key, error) {
	return c.keyCall(ctx, http.MethodGet, keyID, "", nil, retryIfTransient)
}

// RenameKey gives a key a new name, held to the rules of
// [CreateKeyParams.Name], and returns the key. Nothing else about the key
// changes. An API token needs the rename action. A key pending deletion
// fails with [CodeKeyPendingDeletion], and a name in use with
// [CodeKeyExists].
//
// Renaming a key to the name it has changes nothing, so RenameKey is
// retried like a read.
func (c *Client) RenameKey(ctx context.Context, keyID, name string) (*Key, error) {
	body, err := jsonBody(struct {
		Name string `json:"name"`
	}{name})
	if err != nil {
		return nil, err
	}
	return c.keyCall(ctx, http.MethodPatch, keyID, "", body, retryIfTransient)
}

// DeleteKey puts a key in pending deletion and returns it. From then on the
// key refuses every operation, decrypt and unwrap included, with
// [CodeKeyPendingDeletion]. It is destroyed seven days later, at
// [Key.DestroyAfter], unless it is restored first with [Client.RestoreKey].
// Deleting a paid key stops its billing after the day of the request. An
// API token needs the delete action.
//
// Deleting a key that is already pending deletion changes nothing and
// answers the same, so DeleteKey is retried like a read.
func (c *Client) DeleteKey(ctx context.Context, keyID string) (*Key, error) {
	return c.keyCall(ctx, http.MethodDelete, keyID, "", nil, retryIfTransient)
}

// RotateKey creates a new version of a key, makes it primary, and returns
// the key. Versions beyond the tier's retained count (free 1, wrapped 1,
// software 3, hsm 2) are retired: each keeps decrypting for seven days and
// is listed in [Key.RetiringVersions]. On the free and wrapped tiers every
// rotation retires the previous version, so rewrap everything under it
// within seven days. An API token needs the rotate action.
//
// A key with ten versions retiring fails with
// [CodeTooManyRetiringVersions]. Where billing is configured, a paid key
// whose tenant's billing has lapsed fails with [CodeBillingRequired], and a
// free key at its monthly cap with [CodeOpsCapReached].
//
// RotateKey is not retried once the request may have reached the API: a
// second rotation would retire another version.
func (c *Client) RotateKey(ctx context.Context, keyID string) (*Key, error) {
	return c.keyCall(ctx, http.MethodPost, keyID, "/rotate", nil, retryIfUnprocessed)
}

// RestoreKey takes a key out of pending deletion and returns it, active
// again. The key is then billed as if it had never been deleted. An API
// token needs the restore action. A key that is not pending deletion fails
// with [CodeNotPendingDeletion], and one whose [Key.DestroyAfter] has passed
// with [CodeRestoreWindowClosed].
//
// RestoreKey is not retried once the request may have reached the API.
func (c *Client) RestoreKey(ctx context.Context, keyID string) (*Key, error) {
	return c.keyCall(ctx, http.MethodPost, keyID, "/restore", nil, retryIfUnprocessed)
}

// DestroyKey destroys a key at once, whether or not it is pending deletion.
// This cannot be undone: anything encrypted under the key can never be
// decrypted again, and from then on the key is [CodeNotFound]. It needs a
// console session; an API token fails with [CodeSessionRequired].
//
// DestroyKey is not retried once the request may have reached the API.
func (c *Client) DestroyKey(ctx context.Context, keyID string) error {
	path, err := idPath("keys", "key ID", keyID, "/destroy")
	if err != nil {
		return err
	}
	return c.do(ctx, &request{method: http.MethodPost, path: path, retry: retryIfUnprocessed}, nil)
}

// keyCall makes a call on /v1/keys/{keyID}{suffix} that answers with a key.
func (c *Client) keyCall(ctx context.Context, method, keyID, suffix string, body []byte, retry retryPolicy) (*Key, error) {
	path, err := idPath("keys", "key ID", keyID, suffix)
	if err != nil {
		return nil, err
	}
	var key Key
	if err := c.do(ctx, &request{method: method, path: path, body: body, retry: retry}, &key); err != nil {
		return nil, err
	}
	return &key, nil
}
