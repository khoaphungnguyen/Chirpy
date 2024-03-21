package storage

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

type DB struct {
	path string
	mu   sync.RWMutex
}

type Chirp struct {
	ID   int    `json:"id"`
	Body string `json:"body"`
}

type User struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  map[int]User  `json:"users"`
}

// NewDB creates a new database connection
// and initializes the database file if it doesn't exist.
func NewDB(path string) (*DB, error) {
	db := &DB{path: path}

	// Ensure the database file exists; create it with initial content if it doesn't.
	if err := db.ensureDB(); err != nil {
		return nil, err
	}

	return db, nil
}

// CreateChirp creates a new chirp and saves it to disk.
func (db *DB) CreateChirp(body string) (Chirp, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	newID := len(dbStructure.Chirps) + 1 // Simplified ID generation

	newChirp := Chirp{
		ID:   newID,
		Body: body,
	}

	dbStructure.Chirps[newID] = newChirp

	if err := db.writeDB(dbStructure); err != nil {
		return Chirp{}, err
	}

	return newChirp, nil
}

// CreateUser creates a new user and saves it to disk.
func (db *DB) CreateUser(email string) (User, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	newID := len(dbStructure.Users) + 1 // Simplified ID generation

	newUser := User{
		ID:    newID,
		Email: email,
	}

	dbStructure.Users[newID] = newUser

	if err := db.writeDB(dbStructure); err != nil {
		return User{}, err
	}

	return newUser, nil
}

// GetChirps returns all chirps in the database.
func (db *DB) GetChirps() ([]Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return nil, err
	}
	chirps := make([]Chirp, 0, len(dbStructure.Chirps))

	for _, chirp := range dbStructure.Chirps {
		chirps = append(chirps, chirp)
	}
	return chirps, nil
}

// GetSingleChirp returns a single chirp from the database by ID.
func (db *DB) GetSingleChirp(id int) (Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	chirp, exists := dbStructure.Chirps[id]
	if !exists {
		// If the chirp does not exist, return an appropriate error
		return Chirp{}, errors.New("chirp not found")
	}

	return chirp, nil
}

// ensureDB creates a new database file if it doesn't exist.
func (db *DB) ensureDB() error {
	if _, err := os.Stat(db.path); err != nil {
		if os.IsNotExist(err) {
			return db.writeDB(DBStructure{Chirps: make(map[int]Chirp), Users: make(map[int]User)})
		}
		return err
	}
	return nil
}

// loadDB reads the database file into memory.
func (db *DB) loadDB() (DBStructure, error) {
	data, err := os.ReadFile(db.path)
	if err != nil {
		return DBStructure{}, err
	}

	var dbStructure DBStructure
	if err := json.Unmarshal(data, &dbStructure); err != nil {
		return DBStructure{}, err
	}

	return dbStructure, nil
}

// writeDB writes the database file to disk.
func (db *DB) writeDB(dbStructure DBStructure) error {
	data, err := json.Marshal(dbStructure)
	if err != nil {
		return err
	}

	return os.WriteFile(db.path, data, 0644)
}
