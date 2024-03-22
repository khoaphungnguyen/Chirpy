package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type DB struct {
	path   string
	secret string
	mu     sync.RWMutex
}

type Chirp struct {
	ID       int    `json:"id"`
	AuthorID int    `json:"author_id"`
	Body     string `json:"body"`
}

type User struct {
	ID          int    `json:"id"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	IsChirpyRed bool   `json:"is_chirpy_red"`
}

type RefreshTokenInfo struct {
	UserID    int
	Token     string
	Revoked   bool
	ExpiresAt int64 // Unix timestamp
}

type DBStructure struct {
	Chirps        map[int]Chirp
	Users         map[int]User
	RefreshTokens map[string]RefreshTokenInfo
}

type userResponsePayload struct {
	ID           int    `json:"id"`
	Email        string `json:"email"`
	IsChirpyRed  bool   `json:"is_chirpy_red"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

type NewUserPayload struct {
	ID          int    `json:"id"`
	Email       string `json:"email"`
	IsChirpyRed bool   `json:"is_chirpy_red"`
}

// NewDB creates a new database connection
// and initializes the database file if it doesn't exist.
func NewDB(path string, secret string) (*DB, error) {
	db := &DB{
		path:   path,
		secret: secret,
	}

	// Ensure the database file exists; create it with initial content if it doesn't.
	if err := db.ensureDB(); err != nil {
		return nil, err
	}

	return db, nil
}

// CreateUser creates a new user and saves it to disk.
func (db *DB) CreateUser(email, password string) (NewUserPayload, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return NewUserPayload{}, err
	}

	// Check for unique email
	for _, user := range dbStructure.Users {
		if user.Email == email {
			return NewUserPayload{}, errors.New("email exists")
		}
	}

	newID := len(dbStructure.Users) + 1 // Simplified ID generation, consider more robust ID generation
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return NewUserPayload{}, err
	}

	newUser := User{
		ID:          newID,
		Email:       email,
		Password:    string(hashedPassword),
		IsChirpyRed: false,
	}

	dbStructure.Users[newID] = newUser

	if err := db.writeDB(dbStructure); err != nil {
		return NewUserPayload{}, err
	}

	user := NewUserPayload{
		ID:          newUser.ID,
		Email:       newUser.Email,
		IsChirpyRed: false,
	}

	return user, nil
}

// Login allows a user to login
func (db *DB) LoginUser(email, password string) (userResponsePayload, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	user, err := db.getUserByEmailNoLock(email)
	if err != nil {
		return userResponsePayload{}, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return userResponsePayload{}, errors.New("invalid credentials")
	}

	// Create Token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(1 * time.Hour)),
		Subject:   strconv.Itoa(user.ID),
	})
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy-refresh",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(24 * 60 * time.Hour)),
		Subject:   strconv.Itoa(user.ID),
	})

	// Sign the JWT token and handle potential error
	signedAccessToken, err := accessToken.SignedString([]byte(db.secret))
	if err != nil {
		return userResponsePayload{}, err
	}
	signedRefreshToken, err := refreshToken.SignedString([]byte(db.secret))
	if err != nil {
		return userResponsePayload{}, err
	}

	expiresAt := time.Now().UTC().Add(24 * time.Hour)

	err = db.SaveRefreshTokenWithNoLock(user.ID, signedRefreshToken, expiresAt)
	if err != nil {
		fmt.Printf("Error saving refresh token: %v\n", err)
	}

	payload := userResponsePayload{
		ID:           user.ID,
		Email:        user.Email,
		IsChirpyRed:  user.IsChirpyRed,
		Token:        signedAccessToken,
		RefreshToken: signedRefreshToken,
	}

	return payload, nil
}

// GetUserByEmail returns a single user from the database by email.
func (db *DB) getUserByEmailNoLock(email string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	for _, user := range dbStructure.Users {
		if user.Email == email {
			return user, nil
		}
	}

	return User{}, errors.New("user not found")
}

// GetUserByID returns a single user from the database by ID.
func (db *DB) GetUserByID(id int) (User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	user, exists := dbStructure.Users[id]
	if !exists {
		return User{}, errors.New("user not found")
	}

	return user, nil
}

// UpdateUser updates a user's information, excluding their email.
func (db *DB) UpgradeUser(id int) (bool, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return false, err
	}

	user, exists := dbStructure.Users[id]
	if !exists {
		return false, errors.New("user not found")
	}

	user.IsChirpyRed = true

	dbStructure.Users[id] = user

	if err := db.writeDB(dbStructure); err != nil {
		return false, err
	}
	return true, nil

}

// UpdateUser updates a user's information, excluding their email.
func (db *DB) UpdateUser(id int, updatedUser User) (User, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	user, exists := dbStructure.Users[id]
	if !exists {
		return User{}, errors.New("user not found")
	}

	// Assuming password can be updated, re-hash it
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(updatedUser.Password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	user.Password = string(hashedPassword)
	// Update email if needed, ensure it's unique
	for _, u := range dbStructure.Users {
		if u.Email == updatedUser.Email && u.ID != id {
			return User{}, errors.New("email is already in use by another user")
		}
	}
	user.Email = updatedUser.Email

	dbStructure.Users[id] = user

	if err := db.writeDB(dbStructure); err != nil {
		return User{}, err
	}

	return user, nil
}

// CreateChirp creates a new chirp and saves it to disk.
func (db *DB) CreateChirp(userID int, body string) (Chirp, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	newID := len(dbStructure.Chirps) + 1 // Simplified ID generation

	newChirp := Chirp{
		ID:       newID,
		AuthorID: userID,
		Body:     body,
	}

	dbStructure.Chirps[newID] = newChirp

	if err := db.writeDB(dbStructure); err != nil {
		return Chirp{}, err
	}

	return newChirp, nil
}

// GetChirps returns all chirps in the database.
func (db *DB) GetChirps(userID int, sortOrder string) ([]Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return nil, err
	}
	var chirps []Chirp
	for _, chirp := range dbStructure.Chirps {
		if userID > 0 {
			if chirp.AuthorID == userID {
				chirps = append(chirps, chirp)
			}
		} else {
			chirps = append(chirps, chirp)
		}
	}
	// Sort the chirps based on the sortOrder parameter
	if sortOrder == "desc" {
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].ID > chirps[j].ID
		})
	} else {
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].ID < chirps[j].ID
		})
	}
	return chirps, nil
}

// GetSingleChirp returns a single chirp from the database by ID.
func (db *DB) GetSingleChirp(userID, chirpID int) (Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	chirp, exists := dbStructure.Chirps[chirpID]
	if !exists {
		// If the chirp does not exist, return an appropriate error
		return Chirp{}, errors.New("chirp not found")
	}
	if chirp.AuthorID != userID {
		return Chirp{}, errors.New("unauthorized user")
	}

	return chirp, nil
}

// Delete a single chirp from the database by ID.
func (db *DB) DeleteChirp(userID, chirpID int) (bool, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return false, err
	}

	chirp, exists := dbStructure.Chirps[chirpID]
	if !exists {
		// If the chirp does not exist, return an appropriate error
		return false, errors.New("chirp not found")
	}
	if chirp.AuthorID != userID {
		return false, errors.New("unauthorized user")
	}

	delete(dbStructure.Chirps, chirpID)

	if err := db.writeDB(dbStructure); err != nil {
		return false, err
	}

	return true, nil
}

// RevokeRefreshToken marks a given refresh token as revoked.
func (db *DB) RevokeRefreshToken(token string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}

	// Check if the token exists
	tokenInfo, exists := dbStructure.RefreshTokens[token]
	if !exists {
		return errors.New("token not found")
	}

	// Mark the token as revoked
	tokenInfo.Revoked = true
	dbStructure.RefreshTokens[token] = tokenInfo

	if err := db.writeDB(dbStructure); err != nil {
		return err
	}

	return nil
}

// SaveRefreshToken saves or updates a given refresh token in the database.
func (db *DB) SaveRefreshTokenWithNoLock(userID int, token string, expiresAt time.Time) error {
	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}

	// Save or update the token information
	dbStructure.RefreshTokens[token] = RefreshTokenInfo{
		UserID:    userID,
		Token:     token,
		Revoked:   false, // Active token
		ExpiresAt: expiresAt.Unix(),
	}

	// Persist the updated structure to the database
	if err := db.writeDB(dbStructure); err != nil {
		return err
	}

	return nil
}

// RefreshTokenIsRevoked checks if the given refresh token has been revoked.
func (db *DB) RefreshTokenIsRevoked(token string) (bool, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return false, err // Error loading DB, can't determine token status
	}

	// Check if the token exists
	tokenInfo, exists := dbStructure.RefreshTokens[token]
	if !exists {
		return false, errors.New("token not found") // Token not found; treat as revoked or handle appropriately
	}

	// Return the revoked status of the token
	return tokenInfo.Revoked, nil
}

// ensureDB creates a new database file if it doesn't exist.
func (db *DB) ensureDB() error {
	if _, err := os.Stat(db.path); err != nil {
		if os.IsNotExist(err) {
			return db.writeDB(DBStructure{Chirps: make(map[int]Chirp), Users: make(map[int]User), RefreshTokens: make(map[string]RefreshTokenInfo)})
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
