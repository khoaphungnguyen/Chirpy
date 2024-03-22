package storage

import (
	"encoding/json"
	"errors"
	"os"
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
	ID   int    `json:"id"`
	Body string `json:"body"`
}

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type DBStructure struct {
	Chirps map[int]Chirp   `json:"chirps"`
	Users  map[string]User `json:"users"`
}

type userResponsePayload struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	Token string `json:"token"W`
}

// NewDB creates a new database connection
// and initializes the database file if it doesn't exist.
func NewDB(path string, secret string) (*DB, error) {
	db := &DB{path: path, secret: secret}

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
func (db *DB) CreateUser(email, password string) (userResponsePayload, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, err := db.GetSingleEmail(email)
	if err == nil {
		return userResponsePayload{}, errors.New("email exists")
	}

	dbStructure, err := db.loadDB()
	if err != nil {
		return userResponsePayload{}, err
	}

	newID := len(dbStructure.Users) + 1 // Simplified ID generation
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return userResponsePayload{}, err
	}

	newUser := User{
		ID:       newID,
		Email:    email,
		Password: string(hashedPassword),
	}
	dbStructure.Users[email] = newUser

	if err := db.writeDB(dbStructure); err != nil {
		return userResponsePayload{}, err
	}

	user := userResponsePayload{
		ID:    newUser.ID,
		Email: newUser.Email,
	}

	return user, nil
}

// Login allows a user to login
func (db *DB) Login(email, password string, expiresIn time.Duration) (userResponsePayload, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	user, err := db.GetSingleEmail(email)
	if err != nil {
		return userResponsePayload{}, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return userResponsePayload{}, errors.New("invalid credentials")
	}

	// Create Token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject:   strconv.Itoa(user.ID),
	})

	// Sign the JWT token and handle potential error
	signedToken, err := token.SignedString([]byte(db.secret))
	if err != nil {
		return userResponsePayload{}, err
	}

	payload := userResponsePayload{
		ID:    user.ID,
		Email: user.Email,
		Token: signedToken,
	}

	return payload, nil
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

// GetSingleChirp returns a single chirp from the database by ID.
func (db *DB) GetSingleEmail(email string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	user, exists := dbStructure.Users[email]
	if !exists {
		// If the chirp does not exist, return an appropriate error
		return User{}, errors.New("user not found")
	}

	return user, nil
}

// GetUserByID returns a single user from the database by ID.
func (db *DB) GetUserByID(id int) (User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	for _, user := range dbStructure.Users {
		if user.ID == id {
			return user, nil
		}
	}

	return User{}, errors.New("user not found")
}

// UpdateUser updates a user's information, excluding their email.
func (db *DB) UpdateUser(id int, updatedUser User) (User, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	var userToUpdate *User
	for _, user := range dbStructure.Users {
		if user.ID == id {
			userToUpdate = &user
			break
		}
	}

	if userToUpdate == nil {
		return User{}, errors.New("user not found")
	}


	userToUpdate.Password = updatedUser.Password 
	

	dbStructure.Users[userToUpdate.Email] = *userToUpdate

	if err := db.writeDB(dbStructure); err != nil {
		return User{}, err
	}

	return *userToUpdate, nil
}

// ensureDB creates a new database file if it doesn't exist.
func (db *DB) ensureDB() error {
	if _, err := os.Stat(db.path); err != nil {
		if os.IsNotExist(err) {
			return db.writeDB(DBStructure{Chirps: make(map[int]Chirp), Users: make(map[string]User)})
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
