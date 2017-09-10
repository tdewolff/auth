package auth

import (
	"encoding/json"
	"io"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

type providerUserFunc func(io.Reader) (*User, error)

func defaultUserFunc(r io.Reader) (*User, error) {
	v := struct {
		Name string `json:"name"`
	}{}
	if err := json.NewDecoder(r).Decode(&v); err != nil {
		return nil, err
	}
	return NewUser(v.Name, "email"), nil
}

var providers = map[string]struct {
	name     string
	endpoint oauth2.Endpoint
	scopes   []string
	userURL  string
	userFunc providerUserFunc
}{
	"google": {
		"Google",
		google.Endpoint,
		[]string{"https://www.googleapis.com/auth/userinfo.email"},
		"https://www.googleapis.com/oauth2/v3/userinfo",
		defaultUserFunc,
	},
	"facebook": {
		"Facebook",
		facebook.Endpoint,
		[]string{"public_profile"},
		"https://graph.facebook.com/me",
		defaultUserFunc,
	},
	"github": {
		"GitHub",
		github.Endpoint,
		[]string{"user"},
		"https://api.github.com/user",
		defaultUserFunc,
	},
}

////////////////

type Provider struct {
	id       string
	name     string
	userURL  string
	userFunc providerUserFunc
	config   *oauth2.Config
}

func newProvider(id, clientID, clientSecret, redirectURL string) *Provider {
	provider, ok := providers[id]
	if !ok {
		return nil
	}
	return &Provider{
		id,
		provider.name,
		provider.userURL,
		provider.userFunc,
		&oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     provider.endpoint,
			Scopes:       provider.scopes,
		},
	}
}

func (p *Provider) ID() string {
	return p.id
}

func (p *Provider) Name() string {
	return p.name
}

func (p *Provider) User(code string) (*User, string, string, error) {
	oauthToken, err := p.config.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, "", "", err
	}

	client := p.config.Client(oauth2.NoContext, oauthToken)
	resp, err := client.Get(p.userURL)
	if err != nil {
		return nil, "", "", err
	}
	defer resp.Body.Close()

	user, err := p.userFunc(resp.Body)
	return user, oauthToken.AccessToken, oauthToken.RefreshToken, err
}
