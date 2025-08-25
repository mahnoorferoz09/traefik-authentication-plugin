package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

type Config struct {
	Issuer   string `json:"issuer,omitempty"`
	Audience string `json:"audience,omitempty"`
	Secret   string `json:"secret,omitempty"`
}

func CreateConfig() *Config {
	return &Config{}
}

type JWTPlugin struct {
	next     http.Handler
	name     string
	issuer   string
	audience string
	secret   string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	log.Println("[JWTPlugin] Initializing with config")
	return &JWTPlugin{
		next:     next,
		name:     name,
		issuer:   config.Issuer,
		audience: config.Audience,
		secret:   config.Secret,
	}, nil
}

func (a *JWTPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		log.Println("[JWTPlugin] Missing Authorization header")
		http.Error(rw, "Unauthorized - Missing Authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		log.Println("[JWTPlugin] Invalid Authorization header format")
		http.Error(rw, "Unauthorized - Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Printf("[JWTPlugin] Unexpected signing method: %v", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		log.Println("[JWTPlugin] Using client secret for validation")
		return []byte(a.secret), nil
	})

	if err != nil {
		log.Printf("[JWTPlugin] Error parsing token: %v", err)
		http.Error(rw, "Unauthorized - Invalid token", http.StatusUnauthorized)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		log.Printf("[JWTPlugin] Token claims: %v", claims)

		// Validate issuer
		if claims["iss"] != a.issuer {
			log.Printf("[JWTPlugin] Invalid issuer. Expected: %s, Got: %s", a.issuer, claims["iss"])
			http.Error(rw, "Unauthorized - Invalid issuer", http.StatusUnauthorized)
			return
		}

		// Validate audience
		if claims["aud"] != a.audience {
			log.Printf("[JWTPlugin] Invalid audience. Expected: %s, Got: %s", a.audience, claims["aud"])
			http.Error(rw, "Unauthorized - Invalid audience", http.StatusUnauthorized)
			return
		}

		// Validate user_permissions_version
		if upv, ok := claims["user_permissions_version"]; ok {
			log.Printf("[JWTPlugin] Found user_permissions_version: %v", upv)
		} else {
			log.Println("[JWTPlugin] Missing user_permissions_version in token")
			http.Error(rw, "Unauthorized - Missing user_permissions_version", http.StatusUnauthorized)
			return
		}

		log.Println("[JWTPlugin] Token validation successful")
		a.next.ServeHTTP(rw, req)
	} else {
		log.Println("[JWTPlugin] Invalid token claims")
		http.Error(rw, "Unauthorized - Invalid token claims", http.StatusUnauthorized)
	}
}
