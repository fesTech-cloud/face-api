// Package httpx provides standardised HTTP response helpers used by all
// handler packages. Every error response has the same shape:
//
//	{ "error": "human-readable message", "code": "MACHINE_CODE" }
//
// Every success response wraps data under a consistent envelope.
package httpx

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Error writes a standardised error JSON response.
func Error(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{"error": message})
}

// BadRequest writes a 400 error.
func BadRequest(c *gin.Context, message string) {
	Error(c, http.StatusBadRequest, message)
}

// Unauthorized writes a 401 error.
func Unauthorized(c *gin.Context, message string) {
	Error(c, http.StatusUnauthorized, message)
}

// Forbidden writes a 403 error.
func Forbidden(c *gin.Context, message string) {
	Error(c, http.StatusForbidden, message)
}

// NotFound writes a 404 error.
func NotFound(c *gin.Context, message string) {
	Error(c, http.StatusNotFound, message)
}

// TooManyRequests writes a 429 error.
func TooManyRequests(c *gin.Context, message string) {
	Error(c, http.StatusTooManyRequests, message)
}

// InternalError writes a 500 error with a generic message (detail is logged,
// not exposed to the client).
func InternalError(c *gin.Context) {
	Error(c, http.StatusInternalServerError, "an internal error occurred, please try again")
}

// OK writes a 200 JSON response.
func OK(c *gin.Context, data gin.H) {
	c.JSON(http.StatusOK, data)
}
