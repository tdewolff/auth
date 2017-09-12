package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"golang.org/x/oauth2"
)

type Auth struct {
	issuer        string
	userStore     UserStore
	jwtSecret     []byte
	jwtExpiration time.Duration

	providers    map[string]*Provider
	sessionStore *SessionStore

	corsURL string
}

func New(issuer string, userStore UserStore, jwtSecret []byte, jwtExpiration time.Duration) *Auth {
	return &Auth{
		issuer,
		userStore,
		jwtSecret,
		jwtExpiration,
		map[string]*Provider{},
		StartSessions(),
		"",
	}
}

func (a *Auth) Close() {
	a.sessionStore.Stop()
}

func (a *Auth) SetCORS(clientURL string) {
	a.corsURL = clientURL
}

func (a *Auth) AddProvider(id, clientID, clientSecret, redirectURL string, scopes []string) {
	providerFunc, ok := Providers[id]
	if !ok {
		log.Println("provider doesn't exist:", id)
		return
	}
	a.providers[id] = providerFunc(clientID, clientSecret, redirectURL, scopes)
}

func (a *Auth) GetProvider(id string) *Provider {
	return a.providers[id]
}

type ProviderList struct {
	SessionID string         `json:"sessionId"`
	Providers []ProviderItem `json:"providers"`
}

// ProviderItem is the response for the List request
type ProviderItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url`
}

func (a *Auth) Auth(w http.ResponseWriter, r *http.Request) {
	if a.corsURL != "" {
		w.Header().Set("Access-Control-Allow-Origin", a.corsURL)
		w.Header().Set("Access-Control-Allow-Methods", "GET")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
	}

	if r.Method == "OPTIONS" {
		return
	} else if r.Method != "GET" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	} else if r.Header.Get("Authorization") != "" {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	r.ParseForm()

	// Generate Cross-Site Request Forgery token and set session
	csrf := base64.URLEncoding.EncodeToString(GenerateSecret(32))
	refererURI := r.Form.Get("referer")
	encodedSessionID, ok := a.sessionStore.Add(Session{
		csrf,
		refererURI,
		time.Now().Add(sessionDuration),
	})
	if !ok {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// Generate states for every provider, save them to the session store and generate an authorization URL
	list := ProviderList{encodedSessionID, make([]ProviderItem, 0, len(a.providers))}
	for id, provider := range a.providers {
		state := encodeState(csrf, id, refererURI)
		item := ProviderItem{
			id,
			provider.Name,
			provider.Config.AuthCodeURL(state),
		}
		list.Providers = append(list.Providers, item)
	}

	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(list); err != nil {
		log.Println("could not encode response:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (a *Auth) Token(w http.ResponseWriter, r *http.Request) {
	if a.corsURL != "" {
		w.Header().Set("Access-Control-Allow-Origin", a.corsURL)
		w.Header().Set("Access-Control-Allow-Methods", "GET")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
	}

	if r.Method == "OPTIONS" {
		return
	} else if r.Method != "GET" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	} else if r.Header.Get("Authorization") != "" {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	r.ParseForm()

	// Get code and state parameters, and unpack state
	code := r.Form.Get("code")
	sessionID := r.Form.Get("session_id")
	csrf, providerID, refererURI, err := decodeState(r.Form.Get("state"))
	if err != nil {
		log.Println("decoding state failed:", err)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// Get session
	session, ok := a.sessionStore.Get(sessionID)
	if !ok {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// Check that state equals previously generated state, to ensure that the client requested access through this server
	if csrf != session.csrf || refererURI != session.refererURI {
		log.Printf("bad state: csrf %s != %s or refererURI %s != %s\n", csrf, session.csrf, refererURI, session.refererURI)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

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

	// Login the user
	if !a.userStore.Login(user, providerID, oauthToken) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// Generate JWT and send it back to the client
	jwtString, err := a.generateJWT(user)
	if err != nil {
		log.Println("jwt signing failed:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	v := struct {
		JWT     string `json:"jwt"`
		Referer string `json:"referer"`
	}{
		jwtString,
		refererURI,
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

// Middleware provides authentication middleware for a http.HandlerFunc
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.corsURL != "" {
			w.Header().Set("Access-Control-Allow-Origin", a.corsURL) // prevent CORS error when unauthorized or internal server error
			w.Header().Set("Access-Control-Expose-Headers", "Set-Authorization")
		}

		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		// Retrieve authorization token from header
		var tokenString string
		tokenStrings, ok := r.Header["Authorization"]
		if ok && len(tokenStrings) >= 1 {
			tokenString = strings.TrimPrefix(tokenStrings[0], "Bearer ")
		}
		if tokenString == "" {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// Parse JWT and extract claims
		token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return a.jwtSecret, nil
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		claims, ok := token.Claims.(*UserClaims)
		if !ok || !token.Valid {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		// Validate the user with the database
		if !a.userStore.Validate(&claims.User) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// Renew JWT if more than half the JWT expiration time has expired
		if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) < a.jwtExpiration/2 {
			if tokenString, err := a.generateJWT(&claims.User); err != nil {
				log.Println("could not refresh JWT:", err)
			} else {
				w.Header().Set("Set-Authorization", tokenString)
			}
		}

		// Make user available to the API
		context.Set(r, "user", &claims.User)

		next.ServeHTTP(w, r)
	})
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
func encodeState(csrf, providerID, refererURI string) string {
	values := make(url.Values, 3)
	values.Add("sec", csrf)
	values.Add("prv", providerID)
	values.Add("uri", refererURI)
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
	return values.Get("sec"), values.Get("prv"), values.Get("uri"), nil
}

// generateJWT creates and signs JWT
func (a *Auth) generateJWT(user *User) (string, error) {
	claims := &UserClaims{
		*user,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(a.jwtExpiration).Unix(),
			Issuer:    a.issuer,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(a.jwtSecret)
}
