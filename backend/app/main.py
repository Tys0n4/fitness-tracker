from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from .database import engine
from .database import get_db
from .models import Base
from .models import User
from sqlalchemy.orm import Session

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

Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

logged_in_users = set()

def require_login(email: str):
    if email not in logged_in_users:
        raise HTTPException(status_code=401, detail="Not authenticated")

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

@app.get("/users")
def get_users(
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    users = db.query(User).all()
    return users

@app.post("/register")
def register(user: RegisterRequest, db: Session = Depends(get_db)):
    # 1. Check if user already exists
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        return {"message": "Email already registered."}
    
    # 2. Hash the password
    hashed_password = hash_password(user.password)

    # 3. Create User Object
    new_user = User(
        email=user.email,
        hashed_password=hashed_password
    )

    # 4. Save to database
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User registered successfully."}

@app.post("/login")
def login(user: RegisterRequest, db: Session = Depends(get_db)):
    # 1. Look up user by email
    db_user = db.query(User).filter(User.email == user.email).first()

    if not db_user:
        return {"message": "User not found."}

    # 2. Verify password
    if not verify_password(user.password, db_user.hashed_password):
        return {"message": "Invalid password."}
    
    # 3. Create JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    access_token = create_access_token(
        data={"sub": db_user.email},
        expires_delta=access_token_expires
    )

    return {
        "message": "login successful",
        "access_token": access_token,
        "token_type": "bearer"
    }
