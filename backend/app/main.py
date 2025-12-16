from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta

SECRET_KEY = "super-secret-key-change-later" #this goes into env later
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security = HTTPBearer()

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        token = credentials.credentials

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            email: str = payload.get("sub")

            if email is None:
                raise HTTPException(status_code=401, detail="Invalid token")
            return email
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")

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
def get_users(current_user: str = Depends(get_current_user)):
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
                
                access_token_expires = timedelta(
                    minutes=ACCESS_TOKEN_EXPIRE_MINUTES
                )

                access_token = create_access_token(
                    data={"sub": user.email},
                    expires_delta=access_token_expires
                )

                return {
                    "message": "login successful",
                    "access_token": access_token,
                    "token_type": "bearer"
                }

            # Email found but password incorrect
            return {"message": "Invalid password."}
    
    # No user with that email exists
    return {"message": "User not found."}
