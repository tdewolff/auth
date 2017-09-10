package auth

import (
	"encoding/base64"
	"log"
	"time"

	"github.com/gorilla/securecookie"
)

var sessionDuration = time.Minute * 10
var maxSessions = 10000

type Session struct {
	csrf       string
	refererURI string
	expires    time.Time
}

type SessionStore struct {
	secureSession *securecookie.SecureCookie
	sessions      map[string]Session
	quit          chan struct{}
}

func StartSessions() *SessionStore {
	s := &SessionStore{
		securecookie.New(GenerateSecret(32), nil),
		map[string]Session{},
		make(chan struct{}),
	}

	ticker := time.NewTicker(sessionDuration / 10)
	go func() {
		for {
			select {
			case <-ticker.C:
				s.Clean()
			case <-s.quit:
				ticker.Stop()
				return
			}
		}
	}()

	return s
}

func (s *SessionStore) Stop() {
	close(s.quit)
}

func (s *SessionStore) Clean() {
	// Remove expired sessions
	for id, session := range s.sessions {
		if time.Now().After(session.expires) {
			delete(s.sessions, id)
		}
	}
}

func (s *SessionStore) Add(val Session) (string, bool) {
	if len(s.sessions) > maxSessions {
		return "", false
	}

	id := base64.URLEncoding.EncodeToString(GenerateSecret(32))
	s.sessions[id] = val

	// Encode session ID
	encodedID, err := s.secureSession.Encode("auth", id)
	if err != nil {
		log.Println("could not encode session ID:", err)
		return "", false
	}
	return encodedID, true
}

func (s *SessionStore) Get(encodedID string) (Session, bool) {
	id := ""
	if err := s.secureSession.Decode("auth", encodedID, &id); err != nil {
		log.Println("could not decode session ID:", err)
		return Session{}, false
	}
	return s.sessions[id], true
}
