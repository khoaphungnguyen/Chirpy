package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
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

func handleValidateChirp(w http.ResponseWriter, r *http.Request) {
	// Define a struct with an exported field to receive the JSON input
	type input struct {
		Body string `json:"body"`
	}

	var requestInput input
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&requestInput)
	if err != nil {
		log.Printf("Error decoding request body: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error decoding request body"))
		return
	}

	if len(requestInput.Body) > 140 {
		w.WriteHeader(400)
		w.Write([]byte("Chirp must be 140 characters long or less"))
		return
	}

	targetWords := map[string]bool{
		"kerfuffle": true,
		"sharbert":  true,
		"fornax":    true,
	}

	words := strings.Split(requestInput.Body, " ")

	for i, word := range words {
		if _, exist := targetWords[strings.ToLower(word)]; exist {
			words[i] = "****"
		}
	}
	responseBytes, _ := json.Marshal(map[string]string{"cleaned_body": strings.Join(words, " ")})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(responseBytes)
}

func main() {
	apiCfg := &apiConfig{}
	mux := http.NewServeMux()

	// Serve static files under the /app path
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))

	// Handler for retrieving the number of hits
	mux.HandleFunc("GET /admin/metrics", apiCfg.handleHits)

	// Handler for reseting the number of hits to 0
	mux.HandleFunc("/api/reset", apiCfg.handleReset)

	// Handler for check server's health
	mux.HandleFunc("GET /api/healthz", handleHealth)

	// Handler for validating the chirp's length
	mux.HandleFunc("POST /api/validate_chirp", handleValidateChirp)

	// Wrap the mux with the CORS middleware
	corsMux := middlewareCors(mux)

	// Start the server with corsMux as the handler to apply the CORS middleware
	err := http.ListenAndServe(":8080", corsMux)
	if err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}
}
