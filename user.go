package auth

import (
	"github.com/dgrijalva/jwt-go"
)

type User struct {
	Email     string
	FirstName string
	LastName  string
	Locale    string
}

type UserClaims struct {
	User
	jwt.StandardClaims
}

// UserStore handles user logins with the database
type UserStore interface {
	Get(string) (int64, bool)
	Set(*User) (int64, bool)
	GetTokens(int64) (map[string]string, error)
	SetToken(int64, string, string) error
}
