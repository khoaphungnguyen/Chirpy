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

### Chirps

- **Create a Chirp**

  - **POST** `/api/chirps`
  - **Authorization required**: Yes
  - **Body**: `{"body": "Your chirp content here"}`
  - **Description**: Creates a new chirp with the content provided in the request body. The author is determined based on the authentication token.

- **Get Chirps**

  - **GET** `/api/chirps`
  - **Authorization required**: No
  - **Query Parameters**:
    - `author_id` (optional): Filters the chirps to only those created by the specified user.
    - `sort` (optional): Determines the order of the chirps returned. Can be `asc` for ascending or `desc` for descending by chirp ID. Default is `asc`.
  - **Description**: Retrieves chirps, optionally filtered by author and sorted by ID. Without any query parameters, it returns all chirps sorted by ID in ascending order.
  - **Examples**:
    - Get all chirps: `GET http://localhost:8080/api/chirps`
    - Get chirps by author 2, sorted in ascending order: `GET http://localhost:8080/api/chirps?sort=asc&author_id=2`
    - Get chirps sorted in descending order: `GET http://localhost:8080/api/chirps?sort=desc`

- **Delete a Chirp**
  - **DELETE** `/api/chirps/{chirpID}`
  - **Authorization required**: Yes
  - **Description**: Deletes the chirp with the specified ID. The operation is only allowed if the authenticated user is the author of the chirp.

### Authentication and Users

- **Register User**

  - **POST** `/api/users`
  - **Authorization required**: No
  - **Body**: `{"email": "user@example.com", "password": "securepassword"}`
  - **Description**: Registers a new user with the provided email and password.

- **Update User**

  - **PUT** `/api/users`
  - **Authorization required**: Yes
  - **Body**: `{"email": "newemail@example.com", "password": "newsecurepassword"}`
  - **Description**: Updates the authenticated user's email and password.

- **Authenticate (Login)**

  - **POST** `/api/login`
  - **Authorization required**: No
  - **Body**: `{"email": "user@example.com", "password": "securepassword"}`
  - **Description**: Authenticates the user and returns access and refresh JWT tokens.

- **Refresh Token**

  - **POST** `/api/refresh`
  - **Authorization required**: Yes (with a refresh token)
  - **Description**: Refreshes the access token using a valid refresh token.

- **Revoke Token**
  - **POST** `/api/revoke`
  - **Authorization required**: Yes (with a refresh token)
  - **Description**: Revokes the refresh token, effectively logging out the session.

## Development

Feel free to contribute to the Chirpy API by submitting pull requests or reporting issues. For major changes, please open an issue first to discuss what you would like to change.

## License

Distributed under the MIT License. See `LICENSE` for more information.
