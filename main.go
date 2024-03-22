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

func handleChirps(db *storage.DB, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
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
		createdChirp, err := db.CreateChirp(newChirp.Body)
		if err != nil {
			http.Error(w, "Failed to create chirp", http.StatusInternalServerError)
			return
		}

		// Respond with the created chirp
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(createdChirp)

	case "GET":
		// Retrieve all chirps from the database
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
		http.Error(w, "Only GET and POST methods are supported", http.StatusMethodNotAllowed)
	}
}

func handleChirp(db *storage.DB, w http.ResponseWriter, r *http.Request) {
	chirpID := r.PathValue("chirpID")

	// Convert the chirpID to int
	id, err := strconv.Atoi(chirpID)
	if err != nil {
		http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
		return
	}

	chirp, err := db.GetSingleChirp(id)
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

}

func handleUsers(db *storage.DB, w http.ResponseWriter, r *http.Request) {
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
	default:
		http.Error(w, "Onl POST methods are supported", http.StatusMethodNotAllowed)
	}
}

type requestPayload struct {
	Email           string `json:"email"`
	Password        string `json:"password"`
	ExpiresInSecond int    `json:"expireinsecond"`
}

func handleLogin(secret string, db *storage.DB, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		// Decode the request body into a user struct
		var newUser requestPayload
		if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Create a new user in the database
		user, err := db.Login(newUser.Email, newUser.Password, time.Duration(newUser.ExpiresInSecond))
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

		// Respond with the created chirp
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(user)
	case "PUT":
		authHeader := r.Header.Get("Authorization")
		tokenString := strings.Split(authHeader, " ")

		// Ensure the Authorization header is correctly formatted
		if len(tokenString) != 2 || tokenString[0] != "Bearer" {
			http.Error(w, "Malformed token", http.StatusBadRequest)
			return
		}

		// Decode the request body into a user struct
		var newUser storage.User
		if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
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

		userID, ok := (*claims)["sub"].(string) // The subject field in JWT is typically "sub"
		if !ok {
			http.Error(w, "UserID not found", http.StatusNotFound)
			return
		}

		id, err := strconv.Atoi(userID)
		if err != nil {
			http.Error(w, "UserID conversion error", http.StatusBadRequest)
			return
		}

		updatedUser, err := db.UpdateUser(id, newUser)
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
		http.Error(w, "Onl POST, PUT methods are supported", http.StatusMethodNotAllowed)
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
		handleChirps(db, w, r)
	})
	//  Single Chirp handler
	mux.HandleFunc("GET /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		handleChirp(db, w, r)
	})

	// Users handler
	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		handleUsers(db, w, r)
	})

	// User Login Handler
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		handleLogin(jwtSecret, db, w, r)
	})

	// CORS middleware
	corsMux := middlewareCors(mux)

	// Start the server
	log.Println("Server starting on :8080...")
	if err := http.ListenAndServe(":8080", corsMux); err != nil {
		log.Printf("Error starting server: %s\n", err)
	}
}
