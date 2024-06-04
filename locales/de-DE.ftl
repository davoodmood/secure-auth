# Authentication and Login
invalid-credentials = Ungültige Benutzername oder Passwort.
account-locked = Ihr Konto wurde aufgrund mehrerer fehlgeschlagener Anmeldeversuche gesperrt. Bitte versuchen Sie es später erneut.
user-not-found = Benutzer nicht gefunden
database-error = Datenbankfehler
additional-verification-required = Zusätzliche Überprüfung erforderlich. Überprüfen Sie Ihre E-Mails für das OTP.
additional-verification-required-developer = Zusätzliche Überprüfung erforderlich, kontaktieren Sie den Entwickler, um dies zu behandeln ;)
otp-verified-successfully = OTP erfolgreich verifiziert
invalid-or-expired-otp = Ungültiges oder abgelaufenes OTP
otp-not-found = OTP nicht gefunden
user-id-none = Benutzer-ID ist None
failed-to-update-user = Fehler beim Aktualisieren des Benutzers


# Registration
username-too-short = Username must be at least 3 characters long
invalid-email = Invalid email format
password-length = Password must be at least { $min_length } characters long.
password-uppercase = Password must contain at least one uppercase letter.
password-lowercase = Password must contain at least one lowercase letter.
password-digit = Password must contain at least one digit.
password-special-char = Password must contain at least one special character.
invalid-phone = Invalid phone number format
user-already-exists = User with provided email, username, or phone already exists
failed-to-send-verification-email = Failed to send verification email: { $error }
failed-to-send-verification-text = Failed to send verification text: { $error }

# Verification
email-verified-successfully = Email verified successfully
invalid-verification-token = Invalid verification token
phone-verified-successfully = Phone verified successfully

# Forgot Password
password-reset-email-sent = If your email is registered with us, you will receive a password reset link.

# Reset Password
invalid-reset-token = Invalid reset token
password-reset-successful = Password reset successfully
notify-password-reset-failed = Failed to notify user of password reset

# MFA Setup
mfa-already-enabled = MFA is already enabled for this user
encryption-key-missing = Encryption key not set
encryption-key-invalid = Invalid ENCRYPTION_KEY
encryption-iv-invalid = Invalid ENCRYPTION_IV
failed-to-decode-secret = Failed to decode encrypted secret
invalid-utf8-secret = Invalid UTF-8 sequence in decrypted secret

# MFA Verification
mfa-not-enabled = MFA is not enabled for this user
login-first = You must first login using your credentials.
mfa-not-set-up = MFA not set up for this user
invalid-totp-code = Invalid TOTP code
system-time-error = System time error
mfa-verification-failed = MFA verification failed

# MFA Recovery
base64-decode-error = Base64 decoding error
decryption-error = Decryption error
invalid-utf8-string = Invalid UTF-8 string
environment-variable-error = Environment variable error
mfa-not-enabled = MFA not enabled
invalid-recovery-code = Invalid recovery code
recovery-codes-not-found = Recovery codes not found

# MFA Disable
mfa-disable-success = MFA disabled successfully
mfa-disable-failed = Failed to disable MFA on update

# OAuth2 Login
failed-to-create-google-client = Failed to create Google client: { $error }
failed-to-store-csrf-token = Failed to store CSRF token: { $error }
csrf-token-not-found = CSRF token not found in session.
csrf-token-mismatch = CSRF token mismatch.
failed-to-exchange-code = Failed to exchange code for token: { $error }
failed-to-fetch-user-info = Failed to fetch user info: { $error }
account-temporarily-locked = Account is temporarily locked.

# Rate Limiter (middleware)
failed-to-acquire-lock = Failed to acquire lock
system-time-error = System time error
rate-limit-exceeded = Too Many Requests, 1 per 30 seconds allowed

# Permissions (middleware)
no-token-provided = No token provided
permissions-denied = Permission denied

# JWT Authentication (middleware)
unauthorized = Unauthorized Access


# General Messages
internal-server-error = Interner Serverfehler
message-missing-translation = Übersetzung für { $message_id } fehlt
