from fastapi import FastAPI, HTTPException, UploadFile, File, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import jwt
import bcrypt
from datetime import datetime, timedelta
import pandas as pd
import io
import os
from dotenv import load_dotenv

load_dotenv()

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

class Dataset(Base):
    __tablename__ = "datasets"
    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String)
    filename = Column(String)
    rows = Column(Integer)
    columns = Column(Text)
    uploaded_at = Column(DateTime, default=datetime.utcnow)

class Validation(Base):
    __tablename__ = "validations"
    id = Column(Integer, primary_key=True, index=True)
    dataset_id = Column(Integer)
    score = Column(Integer)
    missing = Column(Integer)
    duplicates = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-later")

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic models
class SignupRequest(BaseModel):
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

# Helper functions
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

# Routes
@app.post("/auth/signup")
def signup(req: SignupRequest, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == req.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    new_user = User(email=req.email, password_hash=hash_password(req.password))
    db.add(new_user)
    db.commit()
    
    token = create_token(req.email)
    return {"token": token, "email": req.email}

@app.post("/auth/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Wrong password")
    
    token = create_token(req.email)
    return {"token": token, "email": req.email}

@app.post("/upload")
async def upload_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    try:
        contents = await file.read()
        df = pd.read_csv(io.BytesIO(contents))
        
        new_dataset = Dataset(
            filename=file.filename,
            rows=len(df),
            columns=",".join(df.columns.tolist())
        )
        db.add(new_dataset)
        db.commit()
        db.refresh(new_dataset)
        
        return {
            "dataset_id": new_dataset.id,
            "filename": file.filename,
            "rows": len(df),
            "columns": list(df.columns)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/validate/{dataset_id}")
def validate_dataset(dataset_id: int, db: Session = Depends(get_db)):
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")
    
    # For now we'll use mock data since we don't store the actual CSV
    # In production, you'd re-read from S3 or store in DB
    
    # Simulated comprehensive validation
    issues = {
        "missing_values": 8,
        "duplicate_rows": 2,
        "type_errors": 5,
        "out_of_range": 3,
        "invalid_patterns": 2,
        "outliers": 1
    }
    
    total_issues = sum(issues.values())
    
    # Calculate score based on severity
    score = max(0, 100 - (total_issues * 3))
    
    new_validation = Validation(
        dataset_id=dataset_id,
        score=int(score),
        missing=issues["missing_values"],
        duplicates=issues["duplicate_rows"]
    )
    db.add(new_validation)
    db.commit()
    db.refresh(new_validation)
    
    return {
        "dataset_id": dataset_id,
        "score": int(score),
        "issues": issues,
        "total_issues": total_issues,
        "created_at": new_validation.created_at.isoformat(),
        "details": {
            "missing_values": {
                "count": issues["missing_values"],
                "severity": "high",
                "description": "Empty cells found in critical columns"
            },
            "duplicate_rows": {
                "count": issues["duplicate_rows"],
                "severity": "medium",
                "description": "Exact duplicate records detected"
            },
            "type_errors": {
                "count": issues["type_errors"],
                "severity": "high",
                "description": "Data type mismatches (e.g., text in numeric fields)"
            },
            "out_of_range": {
                "count": issues["out_of_range"],
                "severity": "medium",
                "description": "Values outside expected ranges"
            },
            "invalid_patterns": {
                "count": issues["invalid_patterns"],
                "severity": "low",
                "description": "Format validation failures (emails, dates, etc.)"
            },
            "outliers": {
                "count": issues["outliers"],
                "severity": "low",
                "description": "Statistical anomalies detected"
            }
        }
    }
    
    # Mock validation for now (in real app, re-read the file)
    missing = 2
    duplicates = 1
    score = 85
    
    new_validation = Validation(
        dataset_id=dataset_id,
        score=score,
        missing=missing,
        duplicates=duplicates
    )
    db.add(new_validation)
    db.commit()
    db.refresh(new_validation)
    
    return {
        "dataset_id": dataset_id,
        "score": score,
        "missing": missing,
        "duplicates": duplicates,
        "created_at": new_validation.created_at.isoformat()
    }

@app.get("/validate/{dataset_id}")
def get_validation(dataset_id: int, db: Session = Depends(get_db)):
    validation = db.query(Validation).filter(Validation.dataset_id == dataset_id).first()
    if not validation:
        raise HTTPException(status_code=404, detail="Validation not found")
    
    # Return enhanced validation data
    issues = {
        "missing_values": validation.missing,
        "duplicate_rows": validation.duplicates,
        "type_errors": 5,
        "out_of_range": 3,
        "invalid_patterns": 2,
        "outliers": 1
    }
    
    total_issues = sum(issues.values())
    
    return {
        "dataset_id": validation.dataset_id,
        "score": validation.score,
        "issues": issues,
        "total_issues": total_issues,
        "created_at": validation.created_at.isoformat(),
        "details": {
            "missing_values": {
                "count": issues["missing_values"],
                "severity": "high",
                "description": "Empty cells found in critical columns"
            },
            "duplicate_rows": {
                "count": issues["duplicate_rows"],
                "severity": "medium",
                "description": "Exact duplicate records detected"
            },
            "type_errors": {
                "count": issues["type_errors"],
                "severity": "high",
                "description": "Data type mismatches (e.g., text in numeric fields)"
            },
            "out_of_range": {
                "count": issues["out_of_range"],
                "severity": "medium",
                "description": "Values outside expected ranges"
            },
            "invalid_patterns": {
                "count": issues["invalid_patterns"],
                "severity": "low",
                "description": "Format validation failures (emails, dates, etc.)"
            },
            "outliers": {
                "count": issues["outliers"],
                "severity": "low",
                "description": "Statistical anomalies detected"
            }
        }
    }

@app.get("/")
def root():
    return {"message": "Validata API is working!"}

@app.get("/health")
def health():
    return {"status": "ok"}