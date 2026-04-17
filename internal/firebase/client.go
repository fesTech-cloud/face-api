package firebase

import (
	"context"
	"fmt"
	"os"

	fb "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

var authClient *auth.Client

// Init initialises the Firebase Admin SDK.
// Credentials are read from FIREBASE_CREDENTIALS_JSON (raw service-account JSON)
// or from the file path in GOOGLE_APPLICATION_CREDENTIALS.
func Init(ctx context.Context) error {
	var app *fb.App
	var err error

	if creds := os.Getenv("FIREBASE_CREDENTIALS_JSON"); creds != "" {
		app, err = fb.NewApp(ctx, nil, option.WithCredentialsJSON([]byte(creds)))
	} else {
		// Falls back to GOOGLE_APPLICATION_CREDENTIALS env var (file path).
		app, err = fb.NewApp(ctx, nil)
	}
	if err != nil {
		return fmt.Errorf("firebase init: %w", err)
	}

	authClient, err = app.Auth(ctx)
	if err != nil {
		return fmt.Errorf("firebase auth client: %w", err)
	}
	return nil
}

// VerifyIDToken verifies a Firebase ID token and returns the decoded token.
func VerifyIDToken(ctx context.Context, idToken string) (*auth.Token, error) {
	if authClient == nil {
		return nil, fmt.Errorf("firebase not initialised")
	}
	return authClient.VerifyIDToken(ctx, idToken)
}
