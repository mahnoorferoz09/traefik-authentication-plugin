package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	RedisAddr string `json:"redisAddr,omitempty"`
	RedisPass string `json:"redisPass,omitempty"`
	RedisDB   int    `json:"redisDB,omitempty"`
	SecretKey string `json:"secretKey,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		RedisAddr: "167.253.104.28:6379",
		RedisPass: "",
		RedisDB:   0,
		SecretKey: "admin123!",
	}
}

type JWTPlugin struct {
	next   http.Handler
	config *Config
	client *redis.Client
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPass,
		DB:       config.RedisDB,
	})

	return &JWTPlugin{
		next:   next,
		config: config,
		client: rdb,
	}, nil
}

func (p *JWTPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(rw, "Missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(p.config.SecretKey), nil
	})

	if err != nil || !token.Valid {
		http.Error(rw, "Invalid token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(rw, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	// ✅ Extract user_id and permission_version from token
	userID := fmt.Sprintf("%v", claims["user_id"])
	tokenVersion := fmt.Sprintf("%v", claims["user_permission_version"])

	if userID == "" || tokenVersion == "" {
		http.Error(rw, "Missing claims", http.StatusUnauthorized)
		return
	}

	// ✅ Fetch latest version from Redis
	ctx := context.Background()
	redisKey := fmt.Sprintf("user:%s:permission_version", userID)
	latestVersion, err := p.client.Get(ctx, redisKey).Result()

	if err != nil {
		http.Error(rw, "Redis lookup failed", http.StatusUnauthorized)
		return
	}

	// ✅ Compare versions
	if latestVersion != tokenVersion {
		http.Error(rw, "Token expired (permissions updated)", http.StatusUnauthorized)
		return
	}

	// ✅ Pass request forward
	p.next.ServeHTTP(rw, req)
}
