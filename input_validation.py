from passlib.hash import bcrypt_sha256  # For password hashing
import re

# Define the hardcoded credentials (replace with secure storage mechanism)
hashed_password = bcrypt_sha256.hash("sairam@123")
valid_username = "sairam bathini"

def check_authentication(username, password):
    # Check if the username exists and the password is correct
    if username == valid_username and bcrypt_sha256.verify(password, hashed_password):
        print("Logged in successfully")
    else:
        print("Login failed")

def validate_email(email):
    # Regular expression pattern for validating email addresses
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    
    # Use the re.match() function to check if the email matches the pattern
    if re.match(pattern, email):
        print("Email ID is valid")
    else:
        print("Invalid Email ID")

# Obtain user inputs
login_username = input("Enter your username: ")
login_password = input("Enter your password: ")
emailID = input("Enter your email ID: ")

# Validate user inputs and perform authentication
validate_email(emailID)
check_authentication(login_username, login_password)
