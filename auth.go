package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

var sessionDuration = time.Minute * 10

func init() {
	gob.Register(User{})
}

type Auth struct {
	sessionStore sessions.Store
	userStore    UserStore

	devURL    string
	providers map[string]*Provider
}

func New(sessionStore sessions.Store, userStore UserStore) *Auth {
	return &Auth{
		sessionStore,
		userStore,
		"",
		map[string]*Provider{},
	}
}

func (a *Auth) SetDevURL(devURL string) {
	a.devURL = devURL
}

func (a *Auth) AddProvider(id, clientID, clientSecret, redirectURL string, scopes []string) {
	providerFunc, ok := Providers[id]
	if !ok {
		log.Println("provider doesn't exist:", id)
		return
	}
	a.providers[id] = providerFunc(clientID, clientSecret, redirectURL, scopes)
}

type ProviderList []ProviderItem

func (s ProviderList) Len() int {
	return len(s)
}
func (s ProviderList) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s ProviderList) Less(i, j int) bool {
	return s[i].Name < s[j].Name
}

// ProviderItem is the response for the List request
type ProviderItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url`
}

func (a *Auth) Auth(w http.ResponseWriter, r *http.Request) {
	if a.devURL != "" {
		w.Header().Set("Access-Control-Allow-Origin", a.devURL)
		w.Header().Set("Access-Control-Allow-Methods", "GET")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	if r.Method == "OPTIONS" {
		return
	} else if r.Method != "GET" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm()

	// Generate Cross-Site Request Forgery token and set session
	csrf := base64.URLEncoding.EncodeToString(GenerateSecret(32))
	referrer := r.Form.Get("referrer")

	session, _ := a.sessionStore.New(r, "auth")
	session.Options.MaxAge = int(sessionDuration.Seconds())
	// session.Options.Secure = true // TODO: use HTTPS
	session.Options.HttpOnly = true
	session.Values["csrf"] = csrf
	session.Values["referrer"] = referrer
	if err := session.Save(r, w); err != nil {
		log.Println("could not save session:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Generate states for every provider, save them to the session store and generate an authorization URL
	providers := ProviderList(make([]ProviderItem, 0, len(a.providers)))
	for id, provider := range a.providers {
		state := encodeState(csrf, referrer, id)
		authURL := provider.Config.AuthCodeURL(state)
		providers = append(providers, ProviderItem{id, provider.Name, authURL})
	}
	sort.Sort(providers)

	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(providers); err != nil {
		log.Println("could not encode response:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (a *Auth) Token(w http.ResponseWriter, r *http.Request) {
	if a.devURL != "" {
		w.Header().Set("Access-Control-Allow-Origin", a.devURL)
		w.Header().Set("Access-Control-Allow-Methods", "GET")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	if r.Method == "OPTIONS" {
		return
	} else if r.Method != "GET" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm()

	// Get code and state parameters, and unpack state
	code := r.Form.Get("code")
	csrf, referrer, providerID, err := decodeState(r.Form.Get("state"))
	if err != nil {
		log.Println("decoding state failed:", err)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// Get session
	session, err := a.sessionStore.New(r, "auth")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	if sessionCSRF, ok := session.Values["csrf"].(string); !ok || csrf != sessionCSRF {
		log.Printf("bad CSRF: %s != %s\n", csrf, sessionCSRF)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	if sessionReferrer, ok := session.Values["referrer"].(string); !ok || referrer != sessionReferrer {
		log.Printf("bad referrer: %s != %s\n", referrer, sessionReferrer)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	delete(session.Values, "csrf")
	delete(session.Values, "referrer")

	// Get provider
	provider, ok := a.providers[providerID]
	if !ok {
		log.Println("provider does not exist:", providerID)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// Get OAuth token and encode to JSON for database storage
	oauthToken, err := provider.Config.Exchange(oauth2.NoContext, code)
	if err != nil {
		log.Printf("OAuth exchange to %v failed: %v\n", providerID, err)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// Get user data from the provider
	client := provider.Config.Client(oauth2.NoContext, oauthToken)
	user, err := provider.User(client)
	if err != nil {
		log.Printf("OAuth request to %v failed: %v\n", providerID, err)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// Login the user and set OAuth token
	if !a.userStore.Login(user) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	if err := a.userStore.SetToken(user, providerID, oauthToken); err != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	session.Values["user"] = *user
	if err := session.Save(r, w); err != nil {
		log.Println("could not save session:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	v := struct {
		User     *User  `json:"user"`
		Referrer string `json:"referrer"`
	}{
		user,
		referrer,
	}

	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Println("could not encode response:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	if a.devURL != "" {
		w.Header().Set("Access-Control-Allow-Origin", a.devURL)
		w.Header().Set("Access-Control-Allow-Methods", "GET")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	if r.Method == "OPTIONS" {
		return
	} else if r.Method != "GET" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	session, err := a.sessionStore.New(r, "auth")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	session.Options.MaxAge = -1
	if err := session.Save(r, w); err != nil {
		log.Println("could not save session:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (a *Auth) Validate(w http.ResponseWriter, r *http.Request) (*User, error) {
	session, err := a.sessionStore.New(r, "auth")
	if err != nil {
		return nil, err
	}

	user, ok := session.Values["user"].(User)
	if !ok {
		fmt.Println(session.Values["user"], user, ok)
		return nil, fmt.Errorf("no user in session")
	}

	// Validate the user with the database
	if !a.userStore.Validate(&user) {
		return nil, fmt.Errorf("invalid user")
	}

	// Renew JWT if more than half the JWT expiration time has expired
	// if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) < a.jwtExpiration/2 {
	// 	if tokenString, err := a.generateJWT(&claims.User); err != nil {
	// 		log.Println("could not refresh JWT:", err)
	// 	} else {
	// 		w.Header().Set("Set-Authorization", tokenString)
	// 	}
	// }
	return &user, nil
}

func (a *Auth) Clients(user *User) (map[string]*http.Client, error) {
	tokens, err := a.userStore.GetTokens(user)
	if err != nil {
		return nil, err
	}

	clients := map[string]*http.Client{}
	for providerID, token := range tokens {
		provider := a.providers[providerID]
		if provider == nil {
			continue
		}
		clients[providerID] = provider.Config.Client(oauth2.NoContext, token)
	}
	return clients, nil
}

// Middleware provides authentication middleware for a http.HandlerFunc
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.devURL != "" {
			w.Header().Set("Access-Control-Allow-Origin", a.devURL) // prevent CORS error when unauthorized or internal server error
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		origin, err := url.Parse(r.Header.Get("Origin"))

		fmt.Println(origin, err, r.URL)

		// TODO: CSRF protection

		user, err := a.Validate(w, r)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		clients, err := a.Clients(user)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// Make user and tokens available to the API
		ctx := r.Context()
		ctx = context.WithValue(ctx, "user", user)
		ctx = context.WithValue(ctx, "clients", clients)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func FromContext(ctx context.Context) (*User, map[string]*http.Client) {
	user, ok := ctx.Value("user").(*User)
	if !ok {
		panic("context has no 'user'")
	}
	clients, ok := ctx.Value("clients").(map[string]*http.Client)
	if !ok {
		panic("context has no 'clients'")
	}
	return user, clients
}

// GenerateSecret returns a byte slice of length n of cryptographically secure random data
func GenerateSecret(n int) []byte {
	secret := make([]byte, n)
	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}
	return secret
}

// decodeState encodes our OAuth state string
func encodeState(csrf, referrer, providerID string) string {
	values := make(url.Values, 3)
	values.Add("csrf", csrf)
	values.Add("ref", referrer)
	values.Add("prv", providerID)
	return base64.URLEncoding.EncodeToString([]byte(values.Encode()))
}

// decodeState decodes our OAuth state string
func decodeState(state string) (string, string, string, error) {
	query, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		return "", "", "", err
	}
	values, err := url.ParseQuery(string(query))
	if err != nil {
		return "", "", "", err
	}
	return values.Get("csrf"), values.Get("ref"), values.Get("prv"), nil
}
