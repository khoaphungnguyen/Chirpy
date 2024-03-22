# Chirpy API

Chirpy API is a backend service designed to handle user interactions for the Chirpy platform, enabling functionalities such as user registration, chirp (tweet) creation, and session management through JWT tokens.

## Features

- **User Management**: Register new users, and update user information.
- **Chirp Handling**: Users can post new chirps, retrieve chirps, and delete their chirps.
- **Authentication**: Utilizes JWT for securing endpoints, distinguishing between access and refresh tokens.
- **Token Management**: Supports token refresh and token revocation to manage user sessions securely.

## Getting Started

### Prerequisites

- Go (Version 1.22 or later recommended)
- An environment for running Go applications

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/khoaphungnguyen/Chirpy
   ```
2. Navigate to the project directory:
   ```
   cd chirpy
   ```
3. Load environment variables (ensure `.env` file is set up correctly):
   ```
   source .env
   ```
4. Run the application:
   ```
   go build -o out && ./out
   ```

### Environment Variables

Make sure your `.env` file includes the following variables:

- `JWT_SECRET`: Secret key used to sign JWT tokens.
- `WEBHOOK_API_KEY`: API key for validating incoming webhook requests.

## API Endpoints

- **POST /api/users**: Register a new user.
- **PUT /api/users**: Update user information (authentication required).
- **POST /api/login**: Authenticate a user and receive access and refresh tokens.
- **POST /api/refresh**: Refresh an access token using a refresh token.
- **POST /api/revoke**: Revoke a refresh token.
- **POST /api/chirps**: Create a new chirp (authentication required).
- **GET /api/chirps**: Retrieve all chirps.
- **GET /api/chirps/{chirpID}**: Retrieve a specific chirp (authentication required).
- **DELETE /api/chirps/{chirpID}**: Delete a specific chirp (authentication required).

## Development

Feel free to contribute to the Chirpy API by submitting pull requests or reporting issues. For major changes, please open an issue first to discuss what you would like to change.

## License

Distributed under the MIT License. See `LICENSE` for more information.
