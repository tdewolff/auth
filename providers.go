package auth

import (
	"encoding/json"
	"net/http"

	"golang.org/x/oauth2"
)

type ProviderFunc func(string, string, string, []string) *Provider

var Providers = map[string]ProviderFunc{
	"google":   Google,
	"facebook": Facebook,
	"github":   GitHub,
}

type UserFunc func(*http.Client) (*User, error)

type Provider struct {
	Name string
	*oauth2.Config
	User UserFunc
}

////////////////

func Google(clientID, clientSecret, redirectURL string, scopes []string) *Provider {
	return &Provider{
		"Google",
		&oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://accounts.google.com/o/oauth2/auth",
				TokenURL: "https://accounts.google.com/o/oauth2/token",
			},
			Scopes: mergeScopes(scopes, []string{"profile", "email", "openid"}),
		},
		func(client *http.Client) (*User, error) {
			resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			v := struct {
				Email string `json:"email"`
				Name  string `json:"name"`
			}{}

			if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
				return nil, err
			}
			return NewUser(v.Name, v.Email), nil
		},
	}
}

func Facebook(clientID, clientSecret, redirectURL string, scopes []string) *Provider {
	return &Provider{
		"Facebook",
		&oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://www.facebook.com/dialog/oauth",
				TokenURL: "https://graph.facebook.com/oauth/access_token",
			},
			Scopes: mergeScopes(scopes, []string{"email"}),
		},
		func(client *http.Client) (*User, error) {
			resp, err := client.Get("https://graph.facebook.com/me?fields=name,email")
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			v := struct {
				Email string `json:"email"`
				Name  string `json:"name"`
			}{}

			if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
				return nil, err
			}
			return NewUser(v.Name, v.Email), nil
		},
	}
}

func GitHub(clientID, clientSecret, redirectURL string, scopes []string) *Provider {
	return &Provider{
		"GitHub",
		&oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://github.com/login/oauth/authorize",
				TokenURL: "https://github.com/login/oauth/access_token",
			},
			Scopes: mergeScopes(scopes, []string{"user"}),
		},
		func(client *http.Client) (*User, error) {
			resp, err := client.Get("https://api.github.com/user")
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			v := struct {
				Email string `json:"email"`
				Name  string `json:"name"`
			}{}

			if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
				return nil, err
			}
			return NewUser(v.Name, v.Email), nil
		},
	}
}

////////////////

func mergeScopes(dst, src []string) []string {
srcLoop:
	for _, srcScope := range src {
		for _, dstScope := range dst {
			if srcScope == dstScope {
				continue srcLoop
			}
		}
		dst = append(dst, srcScope)
	}
	return dst
}
