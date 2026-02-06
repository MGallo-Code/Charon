// Package auth contains HTTP handlers and core authentication logic.
//
// handler.go -- HTTP handlers for all /auth/* endpoints.
// Registers routes on a chi router, returns JSON responses.
// Delegates to session, password, and csrf packages for logic.
package auth
