import re
import bcrypt  # For password hashing

# Define the hardcoded credentials (replace with secure storage mechanism)
hashed_password = bcrypt.hashpw(b"sairam@123", bcrypt.gensalt())
valid_username = "sairam bathini"

def check_authentication(username, password):
    # Check if the username exists and the password is correct
    if username == valid_username and bcrypt.checkpw(password.encode(), hashed_password):
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
