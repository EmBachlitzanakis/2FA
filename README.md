# Go Authentication System with 2FA

This is a simple user authentication system implemented in Go using the Gin framework and TOTP (Time-based One-Time Password) for two-factor authentication (2FA). Users can sign up, log in, and enable/verify 2FA for added security.

## Features

- User registration with hashed passwords
- User login with username and password
- Two-factor authentication (2FA) using TOTP
- QR code generation for easy 2FA setup
- Simple JSON-based API

## Technologies Used

- Go
- Gin Gonic
- TOTP (Time-based One-Time Password)
- bcrypt for password hashing

## Getting Started

### Prerequisites

- Go (version 1.16 or higher)
- Git
- sqlit

### Installation

1. **Clone the repository**:
2. **Enter your folder**:
    ```bash
    cd 2fa
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
    - `200 OK` if successful
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

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Gin Gonic](https://github.com/gin-gonic/gin) - Web framework for Go.
- [pquerna/otp](https://github.com/pquerna/otp) - TOTP library for Go.
- [golang.org/x/crypto/bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt) - Password hashing library.
- [auth-microservice](https://github.com/rfashwall/auth-microservice) - auth microservices
