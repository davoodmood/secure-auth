# secure-auth

secure-auth is a secure and feature-rich web application that provides robust user authentication with support for multi-factor authentication (MFA) to enhance security. This application uses modern technologies like Rust, MongoDB, and various cryptographic techniques to ensure secure handling of user data.

## Features

### 1. User Registration
- **Create an Account:** Users can sign up by providing a username, email, and password.
- **Email and Phone Verification:** Ensures that users verify their email and phone number before accessing the services.

### 2. User Login
- **Password Authentication:** Users can log in using their username or email along with their password.
- **Multi-Factor Authentication (MFA):** If enabled, users are prompted for an additional MFA code after entering their password.

### 3. Multi-Factor Authentication (MFA)
- **TOTP-Based MFA:** Uses Time-based One-Time Passwords (TOTP) for MFA, compatible with apps like Google Authenticator.
- **MFA Setup:**
  - Generates a TOTP secret for the user.
  - Provides a QR code for easy scanning by authentication apps.
  - Encrypts and stores the TOTP secret securely in the database.
- **MFA Verification:**
  - Verifies the TOTP code entered by the user.
  - Issues an access token upon successful verification.

### 4. Security
- **Password Hashing:** Uses secure hashing algorithms to store passwords.
- **Encrypted Data Storage:** Encrypts sensitive data like TOTP secrets before storing them in the database.
- **Recovery Codes:** Generates and securely stores recovery codes for account recovery.

### 5. Token-Based Authentication
- **Access Tokens:** Issues JWT tokens for authenticated sessions.
- **Token Management:** Handles token creation and validation to manage user sessions.

## Installation

To run Secure Auth, you need to have Rust and MongoDB installed on your machine. Follow the steps below to set up the application.

### Prerequisites

- Rust (latest stable version)
- MongoDB

### Steps

1. **Clone the Repository:**
```sh
   git clone https://github.com/yourusername/secure-auth.git
   cd secure-auth
```
2. **Set Up Environment Variables:**
   Create a .env file in the root directory and add the following environment variables:
```env
    MONGODB_URI="mongodb://localhost:27017"
    MONGODB_NAME="AuthenticationSystem"
    JWT_SECRET="SOME-SECRET"
    JWT_RESET_SECRET="SOME-OTHER-RESET-TOKEN"
    SMTP_SERVER="send.ahasend.com" # Or your smtp provider
    SMTP_USERNAME="your-smtp-username"
    SMTP_PASSWORD="your-smtp-password"
    SERVER_DOMAIN="your-domain-server" # example.com
    MFA_ISSUER="Your Company Name" #Your brand/company name that shows up in user's authenticator

    # Your_base64_encoded_32_byte_key, 32_byte_key like 'mDFmCpcKsI5elbTZgOqRd0hobFobrPkv'
    ENCRYPTION_KEY="bURGbUNwY0tzSTVlbGJUWmdPcVJkMGhvYkZvYnJQa3Y=" # <- base64 encoded of the key (change this)
    
    # Your_base64_encoded_16_byte_iv # 16_byte_iv like 'oHlnHr8DAjfCyB1W'
    ENCRYPTION_IV="b0hsbkhyOERBamZDeUIxVw==" # <- base64 encoded of the iv (change this)
    
```

3. **Install Dependencies:**
```sh
   cargo build
```

4. **cargo run**
```sh
   cargo build
```

## API Endpoints
1. **User Registration**
- Endpoint: `/register`
- Method: POST
- Request Body:
```json
{
    "username": "johndoe",
    "email": "johndoe@example.com",
    "password": "yourpassword"
}
```
2. **User Login**
- Endpoint: `/login`
- Method: POST
- Request Body:
```json
{
    "identifier": "johndoe", // username or email
    "password": "yourpassword"
}
```

2. **Verify Email**
- Endpoint: `/verify_email`
- Method: `GET`
- URL:
```js
//@notice: Verification token will be automatically send to user's email
// then user will be verified and redirected to your frontend's "/verification-success" 
`https://your-server-domain.com/verify_email?token=${verification_token}`
```

3. **Setup MFA**
- Endpoint: `/setup_mfa/{user_id}`
- Method: `POST`
- Response: Returns a QR code for TOTP setup, with additional data e.g. `MFA recovery codes`.


4. **Verify MFA**
- Endpoint: `/verify_mfa/{user_id}`
- Method: `POST`
- Request Body:
```json
{
    "totp_code": "123456"
}
```

5. **Forgot Password**
- Endpoint: `/forgot_password`
- Method: `POST`
- Request Body:
```json
{
    "email": "johndoe@example.com"
}
```


6. **Reset Password**
- Endpoint: `/reset_password`
- Method: `POST`
- Request Body:
```json
{
    "email": "johndoe@example.com",
    "new_password": "a-new-password", // "String" type
    "reset_token": "get-reset-token-from-frontend-url-param-&-put-here",
}
```

## Contributing
We welcome contributions to Secure-auth. If you find a bug or have a feature request, please open an issue or submit a pull request.

### License
Secure-auth is licensed under the MIT License. See the LICENSE file for more information.

### Acknowledgements
Special thanks to all contributors and the open-source community for their invaluable support and contributions.

