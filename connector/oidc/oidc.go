// Package oidc implements logging in through OpenID Connect providers.
package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	oidc "github.com/coreos/go-oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	ldap "gopkg.in/ldap.v2"

	"github.com/dexidp/dex/connector"
)

var ldapUserAttrList = []string{"mail", "gecos"}

// LDAP properties, hardcoded for first try
const (
	network        string = "tcp"
	tlsHostAddress string = "localhost:636"
	hostAddress    string = "localhost:389"
	rootPEM        string = `-----BEGIN CERTIFICATE-----
	MIIEBDCCAuygAwIBAgIDAjppMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
	MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
	YWwgQ0EwHhcNMTMwNDA1MTUxNTU1WhcNMTUwNDA0MTUxNTU1WjBJMQswCQYDVQQG
	EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy
	bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
	AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
	VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
	h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
	ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
	EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
	DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB+zCB+DAfBgNVHSMEGDAWgBTAephojYn7
	qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wEgYD
	VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwOgYDVR0fBDMwMTAvoC2g
	K4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9ndGdsb2JhbC5jcmwwPQYI
	KwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vZ3RnbG9iYWwtb2NzcC5n
	ZW90cnVzdC5jb20wFwYDVR0gBBAwDjAMBgorBgEEAdZ5AgUBMA0GCSqGSIb3DQEB
	BQUAA4IBAQA21waAESetKhSbOHezI6B1WLuxfoNCunLaHtiONgaX4PCVOzf9G0JY
	/iLIa704XtE7JW4S615ndkZAkNoUyHgN7ZVm2o6Gb4ChulYylYbc3GrKBIxbf/a/
	zG+FA1jDaFETzf3I93k9mTXwVqO94FntT0QJo544evZG0R0SnU++0ED8Vf4GXjza
	HFa9llF7b1cq26KqltyMdMKVvvBulRP/F/A8rLIQjcxz++iPAsbw+zOzlTvjwsto
	WHPbqCRiOwY1nQ2pM714A5AuTHhdUDqB1O6gyHA43LL5Z/qHQF1hwFGPa4NrzQU6
	yuGnBXj8ytqU0CwIPX4WecigUCAkVDNx
	-----END CERTIFICATE-----`
)

// Config holds configuration options for OpenID Connect logins.
type Config struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	RedirectURI  string `json:"redirectURI"`

	// Causes client_secret to be passed as POST parameters instead of basic
	// auth. This is specifically "NOT RECOMMENDED" by the OAuth2 RFC, but some
	// providers require it.
	//
	// https://tools.ietf.org/html/rfc6749#section-2.3.1
	BasicAuthUnsupported *bool `json:"basicAuthUnsupported"`

	Scopes []string `json:"scopes"` // defaults to "profile" and "email"

	// Optional list of whitelisted domains when using Google
	// If this field is nonempty, only users from a listed domain will be allowed to log in
	HostedDomains []string `json:"hostedDomains"`

	// Manually provided endpoints.
	AuthURL  string
	TokenURL string
	JWKURL   string
}

// Domains that don't support basic auth. golang.org/x/oauth2 has an internal
// list, but it only matches specific URLs, not top level domains.
var brokenAuthHeaderDomains = []string{
	// See: https://github.com/dexidp/dex/issues/859
	"okta.com",
	"oktapreview.com",
}

// Detect auth header provider issues for known providers. This lets users
// avoid having to explicitly set "basicAuthUnsupported" in their config.
//
// Setting the config field always overrides values returned by this function.
func knownBrokenAuthHeaderProvider(issuerURL string) bool {
	if u, err := url.Parse(issuerURL); err == nil {
		for _, host := range brokenAuthHeaderDomains {
			if u.Host == host || strings.HasSuffix(u.Host, "."+host) {
				return true
			}
		}
	}
	return false
}

// golang.org/x/oauth2 doesn't do internal locking. Need to do it in this
// package ourselves and hope that other packages aren't calling it at the
// same time.
var registerMu = new(sync.Mutex)

func registerBrokenAuthHeaderProvider(url string) {
	registerMu.Lock()
	defer registerMu.Unlock()

	oauth2.RegisterBrokenAuthHeaderProvider(url)
}

// Open returns a connector which can be used to login users through an upstream
// OpenID Connect provider.
func (c *Config) Open(id string, logger logrus.FieldLogger) (conn connector.Connector, err error) {
	ctx, cancel := context.WithCancel(context.Background())

	var (
		endpoint        oauth2.Endpoint
		idTokenVerifier *oidc.IDTokenVerifier
		verifierConfig  = &oidc.Config{ClientID: c.ClientID}
	)

	if c.TokenURL == "" {
		provider, err := oidc.NewProvider(ctx, c.Issuer)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to get provider: %v", err)
		}

		endpoint = provider.Endpoint()
		idTokenVerifier = provider.Verifier(verifierConfig)
	} else {
		endpoint = oauth2.Endpoint{
			AuthURL:  c.AuthURL,
			TokenURL: c.TokenURL,
		}

		idTokenVerifier = oidc.NewVerifier(
			c.Issuer,
			oidc.NewRemoteKeySet(ctx, c.JWKURL),
			verifierConfig,
		)
	}

	if c.BasicAuthUnsupported != nil {
		// Setting "basicAuthUnsupported" always overrides our detection.
		if *c.BasicAuthUnsupported {
			registerBrokenAuthHeaderProvider(endpoint.TokenURL)
		}
	} else if knownBrokenAuthHeaderProvider(c.Issuer) {
		registerBrokenAuthHeaderProvider(endpoint.TokenURL)
	}

	scopes := []string{oidc.ScopeOpenID}
	if len(c.Scopes) > 0 {
		scopes = append(scopes, c.Scopes...)
	} else {
		scopes = append(scopes, "profile", "email")
	}

	// clientID := c.ClientID
	return &oidcConnector{
		redirectURI: c.RedirectURI,
		oauth2Config: &oauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Endpoint:     endpoint,
			Scopes:       scopes,
			RedirectURL:  c.RedirectURI,
		},
		verifier:      idTokenVerifier,
		logger:        logger,
		cancel:        cancel,
		hostedDomains: c.HostedDomains,
	}, nil
}

var (
	_ connector.CallbackConnector = (*oidcConnector)(nil)
	_ connector.RefreshConnector  = (*oidcConnector)(nil)
)

type oidcConnector struct {
	redirectURI   string
	oauth2Config  *oauth2.Config
	verifier      *oidc.IDTokenVerifier
	ctx           context.Context
	cancel        context.CancelFunc
	logger        logrus.FieldLogger
	hostedDomains []string
}

func (c *oidcConnector) Close() error {
	c.cancel()
	return nil
}

func (c *oidcConnector) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q", callbackURL, c.redirectURI)
	}

	if len(c.hostedDomains) > 0 {
		preferredDomain := c.hostedDomains[0]
		if len(c.hostedDomains) > 1 {
			preferredDomain = "*"
		}
		return c.oauth2Config.AuthCodeURL(state, oauth2.SetAuthURLParam("hd", preferredDomain)), nil
	}
	return c.oauth2Config.AuthCodeURL(state), nil
}

type oauth2Error struct {
	error            string
	errorDescription string
}

func (e *oauth2Error) Error() string {
	if e.errorDescription == "" {
		return e.error
	}
	return e.error + ": " + e.errorDescription
}

func (c *oidcConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, &oauth2Error{errType, q.Get("error_description")}
	}
	// Exchange converts an authorization code into a token.
	token, err := c.oauth2Config.Exchange(r.Context(), q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("oidc: failed to get token: %v", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return identity, errors.New("oidc: no id_token in token response")
	}
	idToken, err := c.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return identity, fmt.Errorf("oidc: failed to verify ID Token: %v", err)
	}

	var claims struct {
		Username      string `json:"name"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		HostedDomain  string `json:"hd"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return identity, fmt.Errorf("oidc: failed to decode claims: %v", err)
	}

	if len(c.hostedDomains) > 0 {
		found := false
		for _, domain := range c.hostedDomains {
			if claims.HostedDomain == domain {
				found = true
				break
			}
		}

		if !found {
			return identity, fmt.Errorf("oidc: unexpected hd claim %v", claims.HostedDomain)
		}
	}

	identity = connector.Identity{
		UserID:        idToken.Subject,
		Username:      claims.Username,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
	}

	roots := x509.NewCertPool()
	ok = roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		return identity, errors.New("Failed to append LDAP root ca")
	}
	tlsConfig := &tls.Config{RootCAs: roots}

	l, err := ldap.DialTLS(network, tlsHostAddress, tlsConfig)
	if err != nil {
		return identity, err
	}
	defer l.Close()
	userID := identity.UserID

	searchRequest := ldap.NewSearchRequest(
		fmt.Sprintf("uid=%s,dc=dummy,dc=com", userID), // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=*))", // The filter to apply
		ldapUserAttrList,     // A list attributes to retrieve
		nil,
	)
	sr, err := l.Search(searchRequest)
	if err != nil {
		return identity, err
	}
	for _, entry := range sr.Entries {
		// 1. Appreach, all roles are single attributes within a string array
		entitlements := entry.GetAttributeValues("dcxIapAuthGrps")
		fmt.Println(entitlements)
		authGroups := entry.GetAttributeValues("dcxIapEntGrps")
		fmt.Println(authGroups)
		// 2. Approach, all roles in one string with ',' delimiter
		var attrSlice []string
		for _, attr := range ldapUserAttrList {
			values := entry.GetAttributeValues(attr)
			if len(values) > 0 {

				attrSlice = append(attrSlice, strings.Join(values, ","))

			}
		}
		fmt.Println(attrSlice)
	}

	return identity, nil
}

// Refresh is implemented for backwards compatibility, even though it's a no-op.
func (c *oidcConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	return identity, nil
}
