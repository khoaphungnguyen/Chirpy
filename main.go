package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/khoaphungnguyen/Chirpy/internal/storage"
)

type apiConfig struct {
	fileserverHits int
	mu             sync.RWMutex
}

func (cfg *apiConfig) handleHits(w http.ResponseWriter, r *http.Request) {
	cfg.mu.Lock()
	hits := cfg.fileserverHits
	cfg.mu.Unlock()

	// Set the Content-Type header to indicate the response is HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Use fmt.Fprintf to send an HTML response with the dynamic hits value
	fmt.Fprintf(w, `
	<html>
	<body>
		<h1>Welcome, Chirpy Admin</h1>
		<p>Chirpy has been visited %d times!</p>
	</body>
	</html>
	`, hits)
}

// handleReset reset the number of fileserver hits to 0.
func (cfg *apiConfig) handleReset(w http.ResponseWriter, r *http.Request) {
	cfg.mu.Lock()
	cfg.fileserverHits = 0
	cfg.mu.Unlock()

	fmt.Fprintf(w, "Reset Successfully")
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Safely increment the counter
		cfg.mu.Lock()
		cfg.fileserverHits++
		cfg.mu.Unlock()

		// Call the next handler in the chain
		next.ServeHTTP(w, r)
	})
}

// middlewareCors creates a middleware that adds CORS headers to the response.
func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	_, err := w.Write([]byte("OK"))
	if err != nil {
		fmt.Println("Error writing response", err)
	}
}

func handleChirps(secret string, db *storage.DB, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		userID, err := validateToken(r.Header.Get("Authorization"), secret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Decode the request body into a Chirp struct
		var newChirp storage.Chirp
		if err := json.NewDecoder(r.Body).Decode(&newChirp); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Validate chirp length
		if len(newChirp.Body) > 140 {
			http.Error(w, "Chirp must be 140 characters long or less", http.StatusBadRequest)
			return
		}

		// Create a new chirp in the database
		createdChirp, err := db.CreateChirp(userID, newChirp.Body)
		if err != nil {
			if err.Error() == "chirp not found" {
				http.Error(w, err.Error(), http.StatusNotFound)
			} else if err.Error() == "unauthorized user" {
				http.Error(w, "unauthorized user", http.StatusInternalServerError)
			} else {
				http.Error(w, "Failed to create chirp", http.StatusInternalServerError)
			}
			return
		}

		// Respond with the created chirp
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(createdChirp)

	case "GET":
		chirps, err := db.GetChirps()
		if err != nil {
			http.Error(w, "Failed to retrieve chirps", http.StatusInternalServerError)
			return
		}

		// Respond with all chirps
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(chirps)

	default:
		http.Error(w, "Only GET, POST, and DELETE methods are supported", http.StatusMethodNotAllowed)
	}
}

func handleChirp(secret string, db *storage.DB, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		userID, err := validateToken(r.Header.Get("Authorization"), secret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		chirpID := r.PathValue("chirpID")

		// Convert the chirpID to int
		id, err := strconv.Atoi(chirpID)
		if err != nil {
			http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
			return
		}

		chirp, err := db.GetSingleChirp(userID, id)
		if err != nil {
			if err.Error() == "chirp not found" { // Check if the error is because the chirp was not found
				http.Error(w, err.Error(), http.StatusNotFound)
			} else {
				http.Error(w, "Failed to retrieve chirp", http.StatusInternalServerError)
			}
			return
		}

		// Respond with all chirps
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(chirp)

	case "DELETE":
		userID, err := validateToken(r.Header.Get("Authorization"), secret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		chirpID := r.PathValue("chirpID")

		// Convert the chirpID to int
		id, err := strconv.Atoi(chirpID)
		if err != nil {
			http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
			return
		}
		//Retrieve all chirps from the database
		_, err = db.DeleteChirp(userID, id)
		if err != nil {
			if err.Error() == "chirp not found" {
				http.Error(w, err.Error(), http.StatusNotFound)
			} else if err.Error() == "unauthorized user" {
				http.Error(w, "unauthorized user", http.StatusForbidden)
			} else {
				http.Error(w, "Failed to create chirp", http.StatusInternalServerError)
			}
			return
		}
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Only GET and DELETE methods are supported", http.StatusMethodNotAllowed)
	}
}

func handleUsers(secret string, db *storage.DB, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		// Decode the request body into a user struct
		var newUser storage.User
		if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Create a new user in the database
		createdUser, err := db.CreateUser(newUser.Email, newUser.Password)
		if err != nil {
			if err.Error() == "email exists" {
				http.Error(w, err.Error(), http.StatusBadRequest)
			} else {
				http.Error(w, "Failed to create a new user", http.StatusInternalServerError)
			}

			return
		}

		// Respond with the created chirp
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(createdUser)
	case "PUT":
		userID, err := validateToken(r.Header.Get("Authorization"), secret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Decode the request body into a user struct
		var newUser storage.User
		if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		updatedUser, err := db.UpdateUser(userID, newUser)
		if err != nil {
			http.Error(w, "Could not update user", http.StatusInternalServerError)
			return
		}

		// Preparing the response
		response := struct {
			Email string `json:"email"`
			ID    int    `json:"id"`
		}{
			Email: updatedUser.Email,
			ID:    updatedUser.ID,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "Error encoding response", http.StatusInternalServerError)
		}
	default:
		http.Error(w, "Only POST and PUT methods are supported", http.StatusMethodNotAllowed)
	}
}

// validateToken parses and validates a JWT token from the Authorization header.
// It returns the userID from the token if the token is valid, otherwise an error.
func validateToken(authHeader string, secret string) (int, error) {
	tokenString := strings.Split(authHeader, " ")
	if len(tokenString) != 2 || tokenString[0] != "Bearer" {
		return 0, fmt.Errorf("malformed token")
	}

	token, err := jwt.ParseWithClaims(tokenString[1], &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return 0, err
	}

	if claims, ok := token.Claims.(*jwt.MapClaims); ok && token.Valid {
		if iss, ok := (*claims)["iss"].(string); !ok || iss != "chirpy-access" {
			return 0, fmt.Errorf("invalid access token")
		}

		userIDStr, ok := (*claims)["sub"].(string)
		if !ok {
			return 0, fmt.Errorf("user ID not found")
		}

		userID, err := strconv.Atoi(userIDStr)
		if err != nil {
			return 0, fmt.Errorf("user ID conversion error")
		}

		return userID, nil
	}

	return 0, fmt.Errorf("invalid token")
}

func handleRefresh(secret string, db *storage.DB, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		authHeader := r.Header.Get("Authorization")
		tokenString := strings.Split(authHeader, " ")

		// Ensure the Authorization header is correctly formatted
		if len(tokenString) != 2 || tokenString[0] != "Bearer" {
			http.Error(w, "Malformed token", http.StatusBadRequest)
			return
		}

		// Parse the token
		token, err := jwt.ParseWithClaims(tokenString[1], &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// Return the secret signing key
			return []byte(secret), nil
		})

		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(*jwt.MapClaims)
		if !ok || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Check if the issuer is correct for an access token
		if iss, ok := (*claims)["iss"].(string); !ok || iss != "chirpy-refresh" {
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
			return
		}

		userID, ok := (*claims)["sub"].(string)
		if !ok {
			http.Error(w, "UserID not found", http.StatusNotFound)
			return
		}

		// Check if it's revoked
		isRevoked, err := db.RefreshTokenIsRevoked(tokenString[1])
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if isRevoked {
			http.Error(w, "Attempt to use a revoked token", http.StatusUnauthorized)
			return
		}

		// Create Token
		accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
			Issuer:    "chirpy-access",
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(1 * time.Hour)),
			Subject:   userID,
		})

		// Sign the JWT token and handle potential error
		signedAccessToken, err := accessToken.SignedString([]byte(secret))
		if err != nil {
			http.Error(w, "Failed to signed the token", http.StatusInternalServerError)
			return
		}

		// Preparing the response
		response := struct {
			Token string `json:"token"`
		}{
			Token: signedAccessToken,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "Error encoding response", http.StatusInternalServerError)
		}
	default:
		http.Error(w, "Only POST methods are supported", http.StatusMethodNotAllowed)
	}
}

func handleRevoke(secret string, db *storage.DB, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		authHeader := r.Header.Get("Authorization")
		tokenString := strings.Split(authHeader, " ")

		// Ensure the Authorization header is correctly formatted
		if len(tokenString) != 2 || tokenString[0] != "Bearer" {
			http.Error(w, "Malformed token", http.StatusBadRequest)
			return
		}

		// Parse the token
		token, err := jwt.ParseWithClaims(tokenString[1], &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// Return the secret signing key
			return []byte(secret), nil
		})

		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(*jwt.MapClaims)
		if !ok || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Check if the issuer is correct for an access token
		if iss, ok := (*claims)["iss"].(string); !ok || iss != "chirpy-refresh" {
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
			return
		}

		_, ok = (*claims)["sub"].(string)
		if !ok {
			http.Error(w, "UserID not found", http.StatusNotFound)
			return
		}
		// marks a given refresh token as revoked

		err = db.RevokeRefreshToken(tokenString[1])
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Only POST methods are supported", http.StatusMethodNotAllowed)
	}
}

type requestPayload struct {
	Email           string `json:"email"`
	Password        string `json:"password"`
	ExpiresInSecond int    `json:"expires_in_seconds"`
}

func handleLogin(db *storage.DB, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		// Decode the request body into a user struct
		var newUser requestPayload
		if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Create a new user in the database
		user, err := db.LoginUser(newUser.Email, newUser.Password)
		if err != nil {
			if err.Error() == "user not found" {
				http.Error(w, "Invalid user or password!", http.StatusNotFound)
			} else if err.Error() == "invalid credentials" {
				http.Error(w, "Invalid user or password!", http.StatusUnauthorized)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		// Respond with the user data
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(user)

	default:
		http.Error(w, "Only POST, PUT methods are supported", http.StatusMethodNotAllowed)
	}
}

func main() {
	apiCfg := &apiConfig{}
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	jwtSecret := os.Getenv("JWT_SECRET")

	// Initialize the DB
	db, err := storage.NewDB("./db.json", jwtSecret)
	if err != nil {
		log.Fatalf("Failed to initialize DB: %v", err)
	}

	mux := http.NewServeMux()

	// Static files handler
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))

	// Metrics handler
	mux.HandleFunc("GET /admin/metrics", apiCfg.handleHits)

	// Reset hits handler
	mux.HandleFunc("GET /api/reset", apiCfg.handleReset)

	// Health check handler
	mux.HandleFunc("GET /api/healthz", handleHealth)

	// Chirps handler
	mux.HandleFunc("/api/chirps", func(w http.ResponseWriter, r *http.Request) {
		handleChirps(jwtSecret, db, w, r)
	})
	//  Single Chirp handler
	mux.HandleFunc("/api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		handleChirp(jwtSecret, db, w, r)
	})

	// Users handler
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		handleUsers(jwtSecret, db, w, r)
	})

	// User Login Handler
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		handleLogin(db, w, r)
	})

	// Refresh token Handler
	mux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) {
		handleRefresh(jwtSecret, db, w, r)
	})

	// Revoke token Handler
	mux.HandleFunc("POST /api/revoke", func(w http.ResponseWriter, r *http.Request) {
		handleRevoke(jwtSecret, db, w, r)
	})

	// CORS middleware
	corsMux := middlewareCors(mux)

	// Start the server
	log.Println("Server starting on :8080...")
	if err := http.ListenAndServe(":8080", corsMux); err != nil {
		log.Printf("Error starting server: %s\n", err)
	}
}
