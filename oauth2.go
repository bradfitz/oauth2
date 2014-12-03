// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package oauth2 provides support for making
// OAuth2 authorized and authenticated HTTP requests.
// It can additionally grant authorization with Bearer JWT.
package oauth2 // import "golang.org/x/oauth2"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/context"
)

// Context can be an golang.org/x/net.Context, or an App Engine Context.
// In the future these will be unified.
// If you don't care and aren't running on App Engine, you may use nil.
type Context interface{}

// Config describes a typical 3-legged OAuth2 flow, with both the
// client application information and the server's URLs.
type Config struct {
	// Client contains the Client ID and Secret.
	Client ClientInfo

	// Endpoint contains the resource server's token endpoint
	// URLs.  These are supplied by the server and are often
	// available via site-specific packages (for example,
	// google.Endpoint or github.Endpoint)
	Endpoint Endpoint

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string

	// Scope specifies optional requested permissions.
	Scopes []string
}

// ClientInfo contains the Client ID and secret.
type ClientInfo struct {
	// ID is the application's Client ID.
	ID string

	// Secret is the application's Client Secret.
	Secret string
}

// A TokenSource is anything that can return a token.
type TokenSource interface {
	Token() (*Token, error)
}

// Endpoint are the OAuth 2.0 provider's authorization and token
// endpoints.
type Endpoint struct {
	AuthURL  string
	TokenURL string
}

// Token represents the crendentials used to authorize
// the requests to access protected resources on the OAuth 2.0
// provider's backend.
type Token struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string `json:"token_type,omitempty"`

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Expiry is the optional expiration time of the access token.
	Expiry time.Time `json:"expiry,omitempty"`

	// raw optionally contains extra metadata from the server
	// when updating a token.
	raw interface{}
}

// Type returns t.TokenType if non-empty, else "Bearer".
func (t *Token) Type() string {
	if t.TokenType != "" {
		return t.TokenType
	}
	return "Bearer"
}

// Extra returns an extra field returned from the server during token
// retrieval.
func (t *Token) Extra(key string) string {
	if vals, ok := t.raw.(url.Values); ok {
		return vals.Get(key)
	}
	if raw, ok := t.raw.(map[string]interface{}); ok {
		if val, ok := raw[key].(string); ok {
			return val
		}
	}
	return ""
}

// Expired returns true if there is no access token or the
// access token is expired.
func (t *Token) Expired() bool {
	if t.AccessToken == "" {
		return true
	}
	if t.Expiry.IsZero() {
		return false
	}
	return t.Expiry.Before(time.Now())
}

var (
	// AccessTypeOnline and AccessTypeOffline control the
	// "access_type" field that gets sent in the URL from
	// AuthCodeURL AuthCodeURL..
	// It may be "online" (default) or "offline".
	// If your application needs to refresh access tokens when the
	// user is not present at the browser, then use offline. This
	// will result in your application obtaining a refresh token
	// the first time your application exchanges an authorization
	// code for a user.
	AccessTypeOnline  AuthCodeOption = setParam{"access_type", "online"}
	AccessTypeOffline AuthCodeOption = setParam{"access_type", "offline"}

	// ApprovalForce forces the users to confirm the permissions
	// request at the URL returned from AuthCodeURL, even if
	// they've already done so.
	ApprovalForce AuthCodeOption = setParam{"approval_prompt", "force"}
)

type setParam struct{ k, v string }

func (p setParam) setValue(m url.Values) { m.Set(p.k, p.v) }

// An AuthCodeOption is passed to Config.AuthCodeURL.
type AuthCodeOption interface {
	setValue(url.Values)
}

// AuthCodeURL returns a URL to OAuth 2.0 provider's consent page
// that asks for permissions for the required scopes explicitly.
//
// State is a token to protect the user from CSRF attacks. You must
// always provide a non-zero string and validate that it matches the
// the state query parameter on your redirect callback.
// See http://tools.ietf.org/html/rfc6749#section-10.12 for more info.
//
// Opts may include AccessTypeOnline or AccessTypeOffline, as well
// as ApprovalForce.
func (c *Config) AuthCodeURL(state string, opts ...AuthCodeOption) string {
	var buf bytes.Buffer
	buf.WriteString(c.Endpoint.AuthURL)
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {c.Client.ID},
		"redirect_uri":  condVal(c.RedirectURL),
		"scope":         condVal(strings.Join(c.Scopes, " ")),
		"state":         condVal(state),
	}
	for _, opt := range opts {
		opt.setValue(v)
	}
	if strings.Contains(c.Endpoint.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String()
}

// exchange converts an "exchange code" into a token.
//
// It is used after a resource provider redirects the user back
// from the URL obtained from AuthCodeURL.
//
// The HTTP client to use is derived from the context. If nil,
// http.DefaultClient is used.
func (c *Config) exchange(ctx Context, code string) (*Token, error) {
	cl := contextClient(ctx)
	return retrieveToken(cl, c, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": condVal(c.RedirectURL),
		"scope":        condVal(strings.Join(c.Scopes, " ")),
	})
}

func contextClient(ctx Context) *http.Client {
	if ctx == nil {
		return http.DefaultClient
	}
	if xc, ok := ctx.(context.Context); ok {
		_ = xc
		panic("TODO: get it from the golang.org/x/net/context.Context")
	}
	panic("TODO: get it from App Engine")
}

// NewTransportFromCode exchanges the code to retrieve a new access token
// and returns an authorized and authenticated Transport.
func (c *Config) NewTransportFromCode(ctx Context, code string) *Transport {
	return &Transport{
		Source: &tokenRefresher{
			conf: c,
			ctx:  ctx,
			code: code,
		},
		Base: contextClient(ctx).Transport,
	}
}

// NewTransportFromToken returns a new Transport using the provided token.
func (c *Config) NewTransportFromToken(ctx Context, t *Token) *Transport {
	return &Transport{
		Source: &tokenRefresher{
			conf: c,
			ctx:  ctx,
			t:    t,
		},
		Base: contextClient(ctx).Transport,
	}
}

// tokenRefresher is a TokenSource that holds a single token in memory
// and validates its expiry before each call to retrieve it with
// Token. If it's expired, it will be auto-refreshed using the
// provided Context.
//
// The first call to TokenRefresher must be SetToken.
type tokenRefresher struct {
	conf *Config
	ctx  Context
	code string // if set, used on first call to populate t

	mu sync.Mutex // guards t
	t  *Token
}

// Token returns the current token if it's still valid, else will
// refresh the current token (using r.Context for HTTP client
// information) and return the new one.
func (r *tokenRefresher) Token() (*Token, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.t == nil {
		if r.code == "" {
			return nil, errors.New("oauth2: attempted use of nil Token")

		}
		t, err := r.conf.exchange(r.ctx, r.code)
		if err != nil {
			return nil, err
		}
		r.t = t
	}
	if !r.t.Expired() {
		return r.t, nil
	}
	if r.t.RefreshToken == "" {
		return nil, errors.New("oauth2: token expired and refresh token is not set")
	}
	t, err := retrieveToken(contextClient(r.ctx), r.conf, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {r.t.RefreshToken},
	})
	if err != nil {
		return nil, err
	}
	r.t = t
	return t, nil
}

func retrieveToken(hc *http.Client, c *Config, v url.Values) (*Token, error) {
	v.Set("client_id", c.Client.ID)
	bustedAuth := !providerAuthHeaderWorks(c.Endpoint.TokenURL)
	if bustedAuth && c.Client.Secret != "" {
		v.Set("client_secret", c.Client.Secret)
	}
	req, err := http.NewRequest("POST", c.Endpoint.TokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !bustedAuth && c.Client.Secret != "" {
		req.SetBasicAuth(c.Client.ID, c.Client.Secret)
	}
	r, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v\nResponse: %s", r.Status, body)
	}

	token := &Token{}
	expires := 0
	content, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch content {
	case "application/x-www-form-urlencoded", "text/plain":
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		token.AccessToken = vals.Get("access_token")
		token.TokenType = vals.Get("token_type")
		token.RefreshToken = vals.Get("refresh_token")
		token.raw = vals
		e := vals.Get("expires_in")
		if e == "" {
			// TODO(jbd): Facebook's OAuth2 implementation is broken and
			// returns expires_in field in expires. Remove the fallback to expires,
			// when Facebook fixes their implementation.
			e = vals.Get("expires")
		}
		expires, _ = strconv.Atoi(e)
	default:
		b := make(map[string]interface{}) // TODO: don't use a map[string]interface{}; make a type
		if err = json.Unmarshal(body, &b); err != nil {
			return nil, err
		}
		token.AccessToken, _ = b["access_token"].(string)
		token.TokenType, _ = b["token_type"].(string)
		token.RefreshToken, _ = b["refresh_token"].(string)
		token.raw = b
		e, ok := b["expires_in"].(float64)
		if !ok {
			// TODO(jbd): Facebook's OAuth2 implementation is broken and
			// returns expires_in field in expires. Remove the fallback to expires,
			// when Facebook fixes their implementation.
			e, _ = b["expires"].(float64)
		}
		expires = int(e)
	}
	// Don't overwrite `RefreshToken` with an empty value
	// if this was a token refreshing request.
	if token.RefreshToken == "" {
		token.RefreshToken = v.Get("refresh_token")
	}
	if expires == 0 {
		token.Expiry = time.Time{}
	} else {
		token.Expiry = time.Now().Add(time.Duration(expires) * time.Second)
	}
	return token, nil
}

func condVal(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}

// providerAuthHeaderWorks reports whether the OAuth2 server identified by the tokenURL
// implements the OAuth2 spec correctly
// See https://code.google.com/p/goauth2/issues/detail?id=31 for background.
// In summary:
// - Reddit only accepts client secret in the Authorization header
// - Dropbox accepts either it in URL param or Auth header, but not both.
// - Google only accepts URL param (not spec compliant?), not Auth header
func providerAuthHeaderWorks(tokenURL string) bool {
	if strings.HasPrefix(tokenURL, "https://accounts.google.com/") ||
		strings.HasPrefix(tokenURL, "https://github.com/") ||
		strings.HasPrefix(tokenURL, "https://api.instagram.com/") ||
		strings.HasPrefix(tokenURL, "https://www.douban.com/") ||
		strings.HasPrefix(tokenURL, "https://api.dropbox.com/") ||
		strings.HasPrefix(tokenURL, "https://api.soundcloud.com/") ||
		strings.HasPrefix(tokenURL, "https://www.linkedin.com/") {
		// Some sites fail to implement the OAuth2 spec fully.
		return false
	}

	// Assume the provider implements the spec properly
	// otherwise. We can add more exceptions as they're
	// discovered. We will _not_ be adding configurable hooks
	// to this package to let users select server bugs.
	return true
}
