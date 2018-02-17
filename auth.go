package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

var authDuration = time.Minute * 10
var jwtDuration = time.Minute * 15
var jwtSecret = []byte("secret")

type jwtClaims struct {
	UserID int64 `json:"uid"`
	jwt.StandardClaims
}

type Auth struct {
	sessionStore sessions.Store
	userStore    UserStore

	cors      string
	providers map[string]*Provider
}

func New(userStore UserStore) *Auth {
	sessionStore := sessions.NewCookieStore(
		[]byte("secret"), // TODO: replace by random below
		// securecookie.GenerateRandomKey(64),
		// securecookie.GenerateRandomKey(32),
	)
	return &Auth{
		sessionStore,
		userStore,
		"",
		map[string]*Provider{},
	}
}

func (a *Auth) SetCORS(cors string) {
	a.cors = cors
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
	ID   string
	Name string
	URL  string
}

func (a *Auth) Auth(w http.ResponseWriter, r *http.Request) {
	if a.cors != "" {
		w.Header().Set("Access-Control-Allow-Origin", a.cors)
		w.Header().Set("Access-Control-Allow-Methods", "GET")
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
	session.Options.MaxAge = int(authDuration.Seconds())
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
	if a.cors != "" {
		w.Header().Set("Access-Control-Allow-Origin", a.cors)
		w.Header().Set("Access-Control-Allow-Methods", "GET")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Expose-Headers", "Set-Authorization")
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
	session.Options.MaxAge = -1
	if err := session.Save(r, w); err != nil {
		log.Println("could not save session:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
	user.Timezone = r.Form.Get("timezone")

	// Login the user and set OAuth token
	userID, ok := a.userStore.Get(user.Email)
	if !ok {
		// Register user
		if userID, ok = a.userStore.Set(user); !ok {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}
	oauthTokenBytes, err := json.Marshal(oauthToken)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	if err := a.userStore.SetToken(userID, providerID, string(oauthTokenBytes)); err != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// Generate JWT and send to client
	tokenString, err := createJWT(userID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Set-Authorization", tokenString)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(referrer); err != nil {
		log.Println("could not encode response:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (a *Auth) Validate(w http.ResponseWriter, r *http.Request) (int64, error) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		return 0, fmt.Errorf("no jwt token")
	}

	token, err := jwt.ParseWithClaims(tokenString, &jwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok || method.Alg() != "HS256" {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return 0, fmt.Errorf("jwt expired")
			}
		}
		return 0, fmt.Errorf("jwt: %v", err)
	}

	if token == nil || !token.Valid {
		return 0, fmt.Errorf("jwt token invalid")
	}

	if claims, ok := token.Claims.(*jwtClaims); ok {
		return claims.UserID, nil
	}
	return 0, fmt.Errorf("jwt claims error")
}

func (a *Auth) Clients(userID int64) (map[string]*http.Client, error) {
	tokens, err := a.userStore.GetTokens(userID)
	if err != nil {
		return nil, err
	}

	clients := map[string]*http.Client{}
	for providerID, token := range tokens {
		var oauthToken *oauth2.Token
		if err := json.Unmarshal([]byte(token), &oauthToken); err != nil {
			return nil, err
		}
		provider := a.providers[providerID]
		if provider == nil {
			continue
		}
		clients[providerID] = provider.Config.Client(oauth2.NoContext, oauthToken)
	}
	return clients, nil
}

// Middleware provides authentication middleware for a http.HandlerFunc
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.cors != "" {
			w.Header().Set("Access-Control-Allow-Origin", a.cors) // prevent CORS error when unauthorized or internal server error
			w.Header().Set("Access-Control-Allow-Headers", "Authorization")
			w.Header().Set("Access-Control-Expose-Headers", "Set-Authorization")
		}

		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		userID, err := a.Validate(w, r)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// Refresh JWT token every request for sliding session expiry
		tokenString, err := createJWT(userID)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Set-Authorization", tokenString)

		clients, err := a.Clients(userID)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// Make user and tokens available to the API
		ctx := r.Context()
		ctx = context.WithValue(ctx, "user", userID)
		ctx = context.WithValue(ctx, "clients", clients)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func FromContext(ctx context.Context) (int64, map[string]*http.Client) {
	userID, ok := ctx.Value("user").(int64)
	if !ok {
		panic("context has no 'user'")
	}
	clients, ok := ctx.Value("clients").(map[string]*http.Client)
	if !ok {
		panic("context has no 'clients'")
	}
	return userID, clients
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

func createJWT(userID int64) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			NotBefore: time.Now().Unix(),
			ExpiresAt: time.Now().Add(jwtDuration).Unix(),
			// TODO: add JTI / nonce
		},
	})
	return token.SignedString(jwtSecret)
}
