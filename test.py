import pyotp

# Replace 'your_secret_key' with the actual secret key
secret_key = 'your_secret_key'

# Create a TOTP object
totp = pyotp.TOTP(secret_key)

# Generate the current OTP code
otp_code = totp.now()

print(otp_code)