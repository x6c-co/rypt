package rypt

import (
	"context"
	"net/http"
	"time"
)

// BillingStatus is where a tenant's subscription stands.
type BillingStatus string

// The billing statuses.
const (
	// BillingNone is a tenant that has no subscription yet.
	BillingNone BillingStatus = "none"
	// BillingActive is a subscription in good standing.
	BillingActive BillingStatus = "active"
	// BillingPastDue is a subscription whose payment failed and is being
	// retried. It is still in good standing.
	BillingPastDue BillingStatus = "past_due"
	// BillingUnpaid is a subscription whose payment retries ran out, with
	// an unpaid invoice open. Paying it in the portal restores good
	// standing.
	BillingUnpaid BillingStatus = "unpaid"
	// BillingLapsed is a subscription that was cancelled, paused or never
	// completed. A new checkout restores good standing.
	BillingLapsed BillingStatus = "lapsed"
)

// Billing is a tenant's billing standing and the current month's estimate.
// Outside good standing, paid keys still decrypt and unwrap, but encrypt,
// wrap, rewrap, rotate and creating a paid key fail with
// [CodeBillingRequired].
type Billing struct {
	// Status is where the subscription stands.
	Status BillingStatus `json:"status"`
	// Period is the UTC month the estimate covers, as "YYYY-MM", always the
	// current one.
	Period string `json:"period"`
	// CancelAt is when the subscription is due to end after a
	// cancellation, or nil when no end is scheduled.
	CancelAt *time.Time `json:"cancel_at"`
	// Estimate is what the month's paid keys and overage come to so far.
	Estimate BillingEstimate `json:"estimate"`
}

// BillingEstimate is what a month's paid keys and overage come to so far,
// before tax. The invoice issued after the month closes is the bill.
type BillingEstimate struct {
	// Currency is an ISO 4217 code in lower case, such as "usd".
	Currency string `json:"currency"`
	// TotalCents is the sum of the lines' AmountCents.
	TotalCents int64 `json:"total_cents"`
	// Lines has one line per paid tier, wrapped, software and hsm in that
	// order, whether or not the tenant has a key on it.
	Lines []BillingLine `json:"lines"`
}

// BillingLine is one paid tier's part of a [BillingEstimate].
type BillingLine struct {
	// Tier is a paid tier.
	Tier Tier `json:"tier"`
	// KeyMonths is how many of the tenant's keys on the tier are billed
	// for the month.
	KeyMonths int64 `json:"key_months"`
	// KeyDays is the days those keys are billed for so far, summed.
	KeyDays int64 `json:"key_days"`
	// DaysInPeriod is how many days the month has.
	DaysInPeriod int64 `json:"days_in_period"`
	// FeeCents is the tier's fee for one key for a whole month, in cents.
	FeeCents int64 `json:"fee_cents"`
	// OverageOps is the operations beyond the included allowance, summed
	// across the tier's keys.
	OverageOps int64 `json:"overage_ops"`
	// OverageMillicentsPerOp is the price of one overage operation, in
	// thousandths of a cent.
	OverageMillicentsPerOp int64 `json:"overage_millicents_per_op"`
	// FeeAmountCents is what the keys' fees come to, in cents.
	FeeAmountCents int64 `json:"fee_amount_cents"`
	// OverageAmountCents is what the overage comes to, in cents.
	OverageAmountCents int64 `json:"overage_amount_cents"`
	// AmountCents is FeeAmountCents plus OverageAmountCents.
	AmountCents int64 `json:"amount_cents"`
}

// BillingSession is a Stripe-hosted page to send a browser to.
type BillingSession struct {
	// URL is the page's address. It is short-lived and specific to the
	// tenant: follow it at once and never store it.
	URL string `json:"url"`
}

// Billing returns the tenant's billing standing and the current month's
// estimate. Where the deployment does not configure billing it fails with
// [CodeNotFound]. It needs a console session.
func (c *Client) Billing(ctx context.Context) (*Billing, error) {
	var billing Billing
	req := &request{method: http.MethodGet, path: "/v1/billing", retry: retryIfTransient}
	if err := c.do(ctx, req, &billing); err != nil {
		return nil, err
	}
	return &billing, nil
}

// CreateCheckoutSession starts a subscription on Stripe Checkout and
// returns the page to send the browser to. A tenant whose subscription is
// still open fails with [CodeBillingActive]; use
// [Client.CreatePortalSession] instead. It needs a console session.
//
// Each call makes a new session, so CreateCheckoutSession is not retried
// once the request may have reached the API.
func (c *Client) CreateCheckoutSession(ctx context.Context) (*BillingSession, error) {
	return c.billingSession(ctx, "/v1/billing/checkout")
}

// CreatePortalSession opens the Stripe customer portal, where invoices, the
// payment method and cancellation are managed, and returns the page to send
// the browser to. A tenant that never started a checkout fails with
// [CodeBillingNotSetUp]. It needs a console session.
//
// Each call makes a new session, so CreatePortalSession is not retried once
// the request may have reached the API.
func (c *Client) CreatePortalSession(ctx context.Context) (*BillingSession, error) {
	return c.billingSession(ctx, "/v1/billing/portal")
}

func (c *Client) billingSession(ctx context.Context, path string) (*BillingSession, error) {
	var session BillingSession
	req := &request{method: http.MethodPost, path: path, retry: retryIfUnprocessed}
	if err := c.do(ctx, req, &session); err != nil {
		return nil, err
	}
	return &session, nil
}
