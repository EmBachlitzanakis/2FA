# Go Authentication System with 2FA, Refresh Tokens, and Authorization

This user authentication system in Go includes **role-based access control (RBAC)** and **refresh tokens**. It supports user registration, login, two-factor authentication (2FA) using TOTP, and secure access to protected routes with role-based permissions.

## Features

- User registration with hashed passwords
- User login with username and password
- Two-factor authentication (2FA) using TOTP
- QR code generation for easy 2FA setup
- JWT-based access tokens for authorization
- Refresh tokens for session management
- Role-based access control (RBAC)
- PostgreSQL integration for data storage
- Simple JSON-based API

## Technologies Used

- **Go**
- **Fiber** - Web framework for Go
- **PostgreSQL** - Database for user data
- **TOTP** - Time-based One-Time Password (for 2FA)
- **bcrypt** - Password hashing
- **JWT** - JSON Web Tokens for authentication
- **Role-Based Access Control (RBAC)** - Authorization based on roles

## Getting Started

### Prerequisites

- Go (version 1.16 or higher)
- Git
- PostgreSQL
- Set up environment variables:
  - `JWT_SECRET` - Secret key for JWT generation
  - `PRIVATE_KEY` - Private key for signing access tokens
  - `PUBLIC_KEY` - Public key for validating access tokens

### Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/EmBachlitzanakis/2fa-authentication-system.git
    ```

2. **Navigate to your project directory**:
    ```bash
    cd 2fa-authentication-system
    ```

3. **Install the dependencies**:
    ```bash
    go mod tidy
    ```

4. **Run the application**:
    ```bash
    go run main.go
    ```

The application will start on `http://localhost:8080`.

## API Endpoints

### 1. User Signup

- **Endpoint**: `POST /auth/signup`
- **Request Body**:
    ```json
    {
        "username": "your_username",
        "password": "your_password",
        "role": "user" // or "admin"
    }
    ```
- **Response**:
    - `201 Created` if successful
    - `409 Conflict` if the username already exists
    - `400 Bad Request` for validation errors

### 2. User Login

- **Endpoint**: `POST /auth/login`
- **Request Body**:
    ```json
    {
        "username": "your_username",
        "password": "your_password"
    }
    ```
- **Response**:
    - `200 OK` if successful, with access and refresh tokens:
        ```json
        {
            "accessToken": "your_jwt_access_token",
            "refreshToken": "your_jwt_refresh_token"
        }
        ```
    - `401 Unauthorized` for invalid credentials
    - `400 Bad Request` for validation errors

### 3. Enable 2FA

- **Endpoint**: `POST /auth/enable-2fa`
- **Request Body**:
    ```json
    {
        "username": "your_username"
    }
    ```
- **Response**:
    - `200 OK` with the 2FA secret and QR code URL if successful
    - `404 Not Found` if the user does not exist
    - `400 Bad Request` for validation errors

### 4. Verify 2FA Code

- **Endpoint**: `POST /auth/verify`
- **Request Body**:
    ```json
    {
        "username": "your_username",
        "code": "your_2fa_code"
    }
    ```
- **Response**:
    - `200 OK` if the code is valid
    - `401 Unauthorized` if the code is invalid
    - `404 Not Found` if the user does not exist
    - `400 Bad Request` for validation errors

### 5. Refresh Token

- **Endpoint**: `POST /auth/refresh`
- **Request Body**:
    ```json
    {
        "refreshToken": "your_refresh_token"
    }
    ```
- **Response**:
    - `200 OK` with a new access token:
        ```json
        {
            "accessToken": "new_jwt_access_token"
        }
        ```
    - `401 Unauthorized` if the refresh token is invalid or expired
    - `400 Bad Request` for validation errors

### 6. Protected Route (Dashboard)

- **Endpoint**: `GET /protected/dashboard`
- **Authorization**: Bearer token required
- **Response**:
    - `200 OK` with a message if the JWT token is valid
    - `403 Forbidden` if the user lacks the necessary role
    - `401 Unauthorized` if the JWT token is invalid or missing

### 7. Role-Based Protected Route

- **Endpoint**: `GET /protected/admin`
- **Authorization**: Bearer token required
- **Response**:
    - `200 OK` with a message if the user has the `admin` role
    - `403 Forbidden` if the user lacks the `admin` role
    - `401 Unauthorized` if the JWT token is invalid or missing

## Enhancements

- **Refresh Token Rotation**: The system rotates refresh tokens on every usage, enhancing security.
- **Role-Based Access Control**: Different routes are restricted based on user roles (e.g., "admin" or "user").
- **Enhanced JWT Structure**:
    - Includes `iss` (issuer), `aud` (audience), `exp` (expiration), `iat` (issued at), and `sub` (subject) claims.
    - Signed with RS256 using a private/public key pair for access tokens.
    - Refresh tokens use HS256 for simpler validation.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


## Acknowledgments


- [pquerna/otp](https://github.com/pquerna/otp) - TOTP library for Go.
- [golang.org/x/crypto/bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt) - Password hashing library.
