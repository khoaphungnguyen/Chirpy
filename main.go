package main

import (
	"fmt"
	"net/http"
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

func main() {
	apiCfg := &apiConfig{}
	mux := http.NewServeMux()

	// Serve static files under the /app path
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))

	// Handler for retrieving the number of hits
	mux.HandleFunc("GET /admin/metrics", apiCfg.handleHits)

	// Handler for reseting the number of hits to 0
	mux.HandleFunc("/api/reset", apiCfg.handleReset)

	// Define the health check endpoint
	mux.HandleFunc("GET /api/healthz", handleHealth)

	// Wrap the mux with the CORS middleware
	corsMux := middlewareCors(mux)

	// Start the server with corsMux as the handler to apply the CORS middleware
	err := http.ListenAndServe(":8080", corsMux)
	if err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}
}
