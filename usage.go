package rypt

import (
	"context"
	"net/http"
	"net/url"
)

// UsageLine is one key's usage in a month.
type UsageLine struct {
	// KeyID is the key.
	KeyID string `json:"key_id"`
	// ContainerID is the container the key lives in, so that the line of a
	// destroyed key can still be placed.
	ContainerID string `json:"container_id"`
	// Ops is the operations performed in the month, including any past the
	// allowance.
	Ops int64 `json:"ops"`
	// OverageOps is how many of Ops were past Allowance. On a paid tier it
	// is what overage is billed on. On the free tier, which refuses rather
	// than allowing overage, it stays 0 but for a few operations that
	// concurrent requests can carry past the cap, which are never billed.
	OverageOps int64 `json:"overage_ops"`
	// Cap is the tier's monthly cap: a hard limit on the free tier, and the
	// included allowance of a paid key that exists all month.
	Cap int64 `json:"cap"`
	// Allowance is the key's included operations for the month. It is Cap,
	// except for a paid key from October 2026 on, whose allowance is split
	// by the days it exists in the month, rounded down.
	Allowance int64 `json:"allowance"`
}

// Usage returns the usage report for a calendar month in UTC: one line per
// live key, including those pending deletion and those that did nothing,
// and one per destroyed key that performed operations in the month. An API
// token sees its container's lines, or only its keys' lines if it is
// restricted to particular keys, and needs the read action.
//
// period is the month as "YYYY-MM", or empty for the current month. Reading
// usage is not metered.
func (c *Client) Usage(ctx context.Context, period string) ([]UsageLine, error) {
	query := url.Values{}
	if period != "" {
		query.Set("period", period)
	}
	var lines []UsageLine
	req := &request{method: http.MethodGet, path: "/v1/usage", query: query, retry: retryIfTransient}
	if err := c.do(ctx, req, &lines); err != nil {
		return nil, err
	}
	return lines, nil
}
