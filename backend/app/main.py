from fastapi import FastAPI
from fastapi import HTTPException
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext

app = FastAPI()

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

users_db = []
logged_in_users = set()

def require_login(email: str):
    if email not in logged_in_users:
        raise HTTPException(status_code=401, detail="Not authenticated")

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

@app.get("/users")
def get_users(email: str):
    require_login(email)
    return users_db

@app.post("/register")
def register(user: RegisterRequest):
    users_db.append({
        "email": user.email,
        "password": hash_password(user.password)
    })

    return {
        "message": "User saved!",
        "users_in_system": len(users_db)
    }

@app.post("/login")
def login(user: RegisterRequest):
    # 1. Look for a user with the same email
    for stored_user in users_db:
        if stored_user["email"] == user.email:
            # 2. Check if the password matches
            if verify_password(user.password, stored_user["password"]):
                logged_in_users.add(user.email)
                return {"message": "Login successful!"}
            
            # Email found but password incorrect
            return {"message": "Invalid password."}
    
    # No user with that email exists
    return {"message": "User not found."}

