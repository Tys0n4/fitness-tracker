from fastapi import FastAPI
from pydantic import BaseModel, EmailStr

app = FastAPI()

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

@app.get("/")
def root():
    return {
        "message": "Welcome to the Fitness Tracker API!"
    }

fake_users =[]

@app.post("/register")
def register(user: RegisterRequest):
    fake_users.append(user.email)
    return {
        "message": "User received!",
        "user_email": user.email,
        "user_password": user.password
    }