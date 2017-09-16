package auth

import (
	"database/sql"
	"encoding/json"
	"log"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
)

type User struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func NewUser(name, email string) *User {
	return &User{
		0,
		name,
		email,
	}
}

type UserClaims struct {
	User
	jwt.StandardClaims
}

// UserStore handles user logins with the database
type UserStore interface {
	Login(*User) bool
	Validate(*User) bool
	SetToken(*User, string, *oauth2.Token) error
	GetTokens(*User) (map[string]*oauth2.Token, error)
}

type DefaultUserStore struct {
	db *sql.DB
}

func NewDefaultUserStore(db *sql.DB) *DefaultUserStore {
	return &DefaultUserStore{db}
}

// Login logs in every user, creating a new account if it is a new user
func (s *DefaultUserStore) Login(user *User) bool {
	// Login or register
	if err := s.db.QueryRow(`SELECT id, name FROM users WHERE email=?`, user.Email).Scan(&user.ID, &user.Name); err != nil && err != sql.ErrNoRows {
		log.Println("userstore login failed:", err)
		return false
	} else if err == sql.ErrNoRows {
		res, err := s.db.Exec(`INSERT INTO users (name, email) VALUES (?, ?)`, user.Name, user.Email)
		if err != nil {
			log.Println("userstore registration failed:", err)
			return false
		}

		user.ID, err = res.LastInsertId()
		if err != nil {
			log.Println("userstore registration failed:", err)
			return false
		}
	}
	return true
}

func (s *DefaultUserStore) Validate(user *User) bool {
	var id int
	if err := s.db.QueryRow(`SELECT id FROM users WHERE id=? AND email=?`, user.ID, user.Email).Scan(&id); err != nil && err != sql.ErrNoRows {
		log.Println("userstore validation failed:", err)
		return false
	} else if err == sql.ErrNoRows {
		return false
	}
	return true
}

func (s *DefaultUserStore) SetToken(user *User, provider string, token *oauth2.Token) error {
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`INSERT INTO social_tokens (user_id, provider, token) VALUES (?, ?, ?)`, user.ID, provider, string(tokenBytes))
	if err != nil {
		return err
	}
	return nil
}

func (s *DefaultUserStore) GetTokens(user *User) (map[string]*oauth2.Token, error) {
	rows, err := s.db.Query(`SELECT provider, token FROM social_tokens WHERE user_id=?`, user.ID)
	if err != nil {
		return nil, err
	}

	tokens := map[string]*oauth2.Token{}
	for rows.Next() {
		var provider string
		var tokenString string
		if err := rows.Scan(&provider, &tokenString); err != nil {
			return nil, err
		}

		var token *oauth2.Token
		if err := json.Unmarshal([]byte(tokenString), &token); err != nil {
			return nil, err
		}
		tokens[provider] = token
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tokens, nil
}
