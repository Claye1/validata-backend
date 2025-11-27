from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import jwt
import bcrypt
from datetime import datetime, timedelta
import pandas as pd
import io

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage
users = {}
datasets = {}
validations = {}

SECRET_KEY = "your-secret-key-change-later"

class SignupRequest(BaseModel):
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_token(email: str) -> str:
    payload = {
        "email": email,
        "exp": datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

@app.post("/auth/signup")
def signup(req: SignupRequest):
    if req.email in users:
        raise HTTPException(status_code=400, detail="User already exists")
    users[req.email] = hash_password(req.password)
    token = create_token(req.email)
    return {"token": token, "email": req.email}

@app.post("/auth/login")
def login(req: LoginRequest):
    if req.email not in users:
        raise HTTPException(status_code=401, detail="User not found")
    if not verify_password(req.password, users[req.email]):
        raise HTTPException(status_code=401, detail="Wrong password")
    token = create_token(req.email)
    return {"token": token, "email": req.email}

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        df = pd.read_csv(io.BytesIO(contents))
        
        dataset_id = len(datasets) + 1
        datasets[dataset_id] = {
            "filename": file.filename,
            "data": df,
            "uploaded_at": datetime.now().isoformat()
        }
        
        return {
            "dataset_id": dataset_id,
            "filename": file.filename,
            "rows": len(df),
            "columns": list(df.columns)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/validate/{dataset_id}")
def validate_dataset(dataset_id: int):
    if dataset_id not in datasets:
        raise HTTPException(status_code=404, detail="Dataset not found")
    
    df = datasets[dataset_id]["data"]
    
    missing = int(df.isnull().sum().sum())
    duplicates = int(df.duplicated().sum())
    
    total_cells = len(df) * len(df.columns)
    issues = missing + duplicates
    score = max(0, 100 - (issues / total_cells * 100))
    
    validation_result = {
        "dataset_id": dataset_id,
        "score": round(score, 2),
        "missing": missing,
        "duplicates": duplicates,
        "created_at": datetime.now().isoformat()
    }
    
    validations[dataset_id] = validation_result
    
    return validation_result

@app.get("/")
def root():
    return {"message": "Validata API is working!"}
@app.get("/validate/{dataset_id}")
def get_validation(dataset_id: int):
    if dataset_id not in validations:
        raise HTTPException(status_code=404, detail="Validation not found")
    return validations[dataset_id]
@app.get("/health")
def health():
    return {"status": "ok"}