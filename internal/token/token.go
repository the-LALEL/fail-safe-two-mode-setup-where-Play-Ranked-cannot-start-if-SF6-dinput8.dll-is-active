// Package token implements the single-use intent token that authorises a
// modded session.
//
// This is the piece that turns "remember to disable the mod" into a property of
// the system rather than a property of the user's memory. The gate launches
// clean unless it is handed a valid token, and only the explicit "Play Modded"
// action mints one. Every other way of starting the game — the Steam library
// button, a desktop shortcut, Big Picture, a friend's invite, a steam:// link —
// arrives with no token and therefore lands in the clean path.
//
// The token is deliberately weak security and strong ergonomics. It is not
// defending against an attacker who already controls the machine; it is
// defending against habit. So it only needs three properties:
//
//   - single-use, so one modded launch cannot authorise a second one later;
//   - short-lived, so a token minted and abandoned cannot sit around waiting to
//     surprise someone tomorrow;
//   - unforgeable by accident, so a stray file called intent.tok does nothing.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// TTL is how long a minted token stays valid.
//
// It covers the gap between clicking "Play Modded" and Steam actually getting
// around to starting the game, which on a cold start with a shader-cache update
// can be slow. Beyond that the token expires: an abandoned launch must not be
// able to authorise a modded session at some arbitrary later point.
const TTL = 90 * time.Second

// KeySize is the length of the machine-local HMAC key.
const KeySize = 32

var (
	// ErrNoToken means no token was present. This is the overwhelmingly common
	// case and is not an error condition — it is the clean path.
	ErrNoToken = errors.New("no intent token present")
	// ErrExpired means a token was found but had aged out.
	ErrExpired = errors.New("intent token expired")
	// ErrBadSignature means a token was found but was not minted by this
	// installation.
	ErrBadSignature = errors.New("intent token signature invalid")
	// ErrWrongApp means the token was minted for a different Steam app.
	ErrWrongApp = errors.New("intent token is for a different app")
)

// Token is the on-disk payload.
type Token struct {
	AppID     string `json:"app_id"`
	Nonce     string `json:"nonce"`
	IssuedAt  int64  `json:"issued_at_unix_nano"`
	Signature string `json:"signature"`
}

func (t *Token) signingPayload() []byte {
	return []byte(fmt.Sprintf("v1|%s|%s|%d", t.AppID, t.Nonce, t.IssuedAt))
}

func sign(key []byte, t *Token) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(t.signingPayload())
	return hex.EncodeToString(mac.Sum(nil))
}

// LoadOrCreateKey returns the machine-local HMAC key, generating it on first
// use. The key never leaves this machine and has no value off it.
func LoadOrCreateKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		key, err := hex.DecodeString(string(data))
		if err == nil && len(key) == KeySize {
			return key, nil
		}
		// A corrupt key file is not worth failing over: regenerating it simply
		// invalidates any outstanding token, which fails safe.
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading token key: %w", err)
	}

	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating token key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		return nil, fmt.Errorf("writing token key: %w", err)
	}
	return key, nil
}

// Mint writes a fresh single-use token to path.
func Mint(path string, key []byte, appID string, now time.Time) error {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}
	t := &Token{
		AppID:    appID,
		Nonce:    hex.EncodeToString(nonce),
		IssuedAt: now.UnixNano(),
	}
	t.Signature = sign(key, t)

	data, err := json.Marshal(t)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// Write via a temporary file and rename, so the gate can never observe a
	// half-written token.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Consume reads, deletes and validates the token at path.
//
// The delete happens before validation and regardless of the outcome: a token
// gets exactly one chance to be used, valid or not. A token that failed to
// validate must not linger to be retried against the next launch.
func Consume(path string, key []byte, appID string, now time.Time) error {
	data, readErr := os.ReadFile(path)

	if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
		// If the token cannot be deleted it could authorise a second launch, so
		// refuse to honour it at all.
		return fmt.Errorf("could not consume intent token (it would remain valid for another launch): %w", removeErr)
	}

	if readErr != nil {
		if os.IsNotExist(readErr) {
			return ErrNoToken
		}
		return fmt.Errorf("reading intent token: %w", readErr)
	}

	var t Token
	if err := json.Unmarshal(data, &t); err != nil {
		return ErrBadSignature
	}

	want := sign(key, &t)
	if !hmac.Equal([]byte(want), []byte(t.Signature)) {
		return ErrBadSignature
	}
	if t.AppID != appID {
		return ErrWrongApp
	}

	age := now.Sub(time.Unix(0, t.IssuedAt))
	if age < 0 || age > TTL {
		return ErrExpired
	}
	return nil
}
