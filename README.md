# Go Authentication System with 2FA

This is a simple user authentication system implemented in Go using the **Fiber** web framework, **MS SQL Server** for the database, and **TOTP** (Time-based One-Time Password) for two-factor authentication (2FA). Users can sign up, log in, enable/verify 2FA, and access protected routes.

## Features

- User registration with hashed passwords
- User login with username and password
- Two-factor authentication (2FA) using TOTP
- QR code generation for easy 2FA setup
- JWT-based authentication for secure access to protected routes
- Simple JSON-based API
- MS SQL Server integration for data storage

## Technologies Used

- Go
- **Fiber** - Web framework for Go
- **MS SQL Server** - Database for user data
- **TOTP** - Time-based One-Time Password (for 2FA)
- **bcrypt** - Password hashing
- **JWT** - JSON Web Tokens for authentication

## Getting Started

### Prerequisites

- Go (version 1.16 or higher)
- Git
- MS SQL Server instance (or use a cloud provider like Azure SQL)
- Set up environment variables:
  - `JWT_SECRET` - Secret key for JWT generation
  - `DB_CONN_STRING` - MS SQL Server connection string (e.g., `sqlserver://username:password@localhost:1433?database=your_db`)

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
        "password": "your_password"
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
    - `200 OK` if successful, with JWT token
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

### 5. Protected Route (Dashboard)

- **Endpoint**: `GET /protected/dashboard`
- **Authorization**: Bearer token required
- **Response**:
    - `200 OK` with a message if the JWT token is valid
    - `401 Unauthorized` if the JWT token is invalid or missing



## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Gin Gonic](https://github.com/gin-gonic/gin) - Web framework for Go.
- [pquerna/otp](https://github.com/pquerna/otp) - TOTP library for Go.
- [golang.org/x/crypto/bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt) - Password hashing library.
- [auth-microservice](https://github.com/rfashwall/auth-microservice) - auth microservices
