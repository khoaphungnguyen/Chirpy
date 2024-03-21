package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"

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
		// Decode the request body into a Chirp struct
		var newUser storage.User
		if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Create a new chirp in the database
		createdUser, err := db.CreateUser(newUser.Email)
		if err != nil {
			http.Error(w, "Failed to create a new user", http.StatusInternalServerError)
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

func main() {
	apiCfg := &apiConfig{}

	// Initialize the DB
	db, err := storage.NewDB("./db.json")
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
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		handleUsers(db, w, r)
	})

	// CORS middleware
	corsMux := middlewareCors(mux)

	// Start the server
	log.Println("Server starting on :8080...")
	if err := http.ListenAndServe(":8080", corsMux); err != nil {
		log.Printf("Error starting server: %s\n", err)
	}
}
