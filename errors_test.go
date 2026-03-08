package authclient

import (
	"errors"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestClassifyJWTError_Malformed(t *testing.T) {
	err := classifyJWTError(jwt.ErrTokenMalformed)
	assert.ErrorIs(t, err, ErrTokenMalformed)
}

func TestClassifyJWTError_Expired(t *testing.T) {
	err := classifyJWTError(jwt.ErrTokenExpired)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestClassifyJWTError_NotYetValid(t *testing.T) {
	err := classifyJWTError(jwt.ErrTokenNotValidYet)
	assert.ErrorIs(t, err, ErrTokenNotYetValid)
}

func TestClassifyJWTError_SignatureInvalid(t *testing.T) {
	err := classifyJWTError(jwt.ErrTokenSignatureInvalid)
	assert.ErrorIs(t, err, ErrTokenInvalid)
}

func TestClassifyJWTError_WrappedMalformed(t *testing.T) {
	wrapped := fmt.Errorf("parse: %w", jwt.ErrTokenMalformed)
	err := classifyJWTError(wrapped)
	assert.ErrorIs(t, err, ErrTokenMalformed)
}

func TestClassifyJWTError_Unverifiable(t *testing.T) {
	err := classifyJWTError(jwt.ErrTokenUnverifiable)
	assert.ErrorIs(t, err, ErrTokenUnverifiable)
}

func TestClassifyJWTError_Unknown(t *testing.T) {
	unknown := errors.New("something unexpected")
	err := classifyJWTError(unknown)
	assert.ErrorIs(t, err, ErrTokenInvalid)
	// S2 security fix: inner error is no longer exposed to prevent information leakage.
	assert.NotErrorIs(t, err, unknown)
}
