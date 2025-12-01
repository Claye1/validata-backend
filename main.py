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
    csv_data = Column(Text)
    uploaded_at = Column(DateTime, default=datetime.utcnow)

class Validation(Base):
    __tablename__ = "validations"
    
    id = Column(Integer, primary_key=True, index=True)
    dataset_id = Column(Integer)
    score = Column(Integer)
    missing = Column(Integer)
    duplicates = Column(Integer)
    type_errors = Column(Integer)
    out_of_range = Column(Integer)
    invalid_patterns = Column(Integer)
    outliers = Column(Integer)
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
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# Routes
@app.get("/")
def read_root():
    return {"message": "Validata API is running"}

@app.post("/auth/signup")
def signup(request: SignupRequest, db: Session = Depends(get_db)):
    # Check if user exists
    existing = db.query(User).filter(User.email == request.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    hashed = hash_password(request.password)
    user = User(email=request.email, password_hash=hashed)
    db.add(user)
    db.commit()
    
    token = create_token(request.email)
    return {"token": token, "email": request.email}

@app.post("/auth/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user or not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(request.email)
    return {"token": token, "email": request.email}

@app.post("/upload")
async def upload_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    try:
        contents = await file.read()
        df = pd.read_csv(io.StringIO(contents.decode('utf-8')))
        
        # Store dataset
        dataset = Dataset(
            user_email="anonymous",
            filename=file.filename,
            rows=len(df),
            columns=str(list(df.columns)),
            csv_data=contents.decode('utf-8')
        )
        db.add(dataset)
        db.commit()
        db.refresh(dataset)
        
        return {
            "dataset_id": dataset.id,
            "filename": file.filename,
            "rows": len(df),
            "columns": len(df.columns)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/dataset/{dataset_id}")
def get_dataset(dataset_id: int, db: Session = Depends(get_db)):
    """Get dataset information for PDF generation"""
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")
    
    return {
        "filename": dataset.filename,
        "rows": dataset.rows,
        "uploaded_at": dataset.uploaded_at.isoformat()
    }

@app.post("/validate/{dataset_id}")
def validate_dataset(dataset_id: int, db: Session = Depends(get_db)):
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")
    
    # Parse CSV
    df = pd.read_csv(io.StringIO(dataset.csv_data))
    
    # 1. Missing values
    missing_values = int(df.isnull().sum().sum())
    
    # 2. Duplicate rows
    duplicate_rows = int(df.duplicated().sum())
    
    # 3. Type errors
    type_errors = 0
    for col in df.columns:
        if df[col].dtype == 'object':
            try:
                numeric_conversion = pd.to_numeric(df[col], errors='coerce')
                if numeric_conversion.notna().sum() > len(df) * 0.5:
                    type_errors += int(numeric_conversion.isna().sum())
            except:
                pass
    
    # 4. Out of range
    out_of_range = 0
    for col in df.select_dtypes(include=['int64', 'float64']).columns:
        Q1 = df[col].quantile(0.25)
        Q3 = df[col].quantile(0.75)
        IQR = Q3 - Q1
        lower_bound = Q1 - 3 * IQR
        upper_bound = Q3 + 3 * IQR
        out_of_range += int(((df[col] < lower_bound) | (df[col] > upper_bound)).sum())
    
    # 5. Invalid patterns
    invalid_patterns = 0
    for col in df.columns:
        if df[col].dtype == 'object':
            if any(keyword in col.lower() for keyword in ['email', 'mail']):
                email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                invalid_patterns += int((~df[col].astype(str).str.match(email_pattern)).sum())
    
    # 6. Outliers (Z-score > 3)
    outliers = 0
    for col in df.select_dtypes(include=['int64', 'float64']).columns:
        mean = df[col].mean()
        std = df[col].std()
        if std > 0:
            z_scores = abs((df[col] - mean) / std)
            outliers += int((z_scores > 3).sum())
    
    # Calculate score
    total_issues = missing_values + duplicate_rows + type_errors + out_of_range + invalid_patterns + outliers
    total_cells = len(df) * len(df.columns)
    score = max(0, int(100 - (total_issues / total_cells) * 100))
    
    # Store validation
    validation = Validation(
        dataset_id=dataset_id,
        score=score,
        missing=missing_values,
        duplicates=duplicate_rows,
        type_errors=type_errors,
        out_of_range=out_of_range,
        invalid_patterns=invalid_patterns,
        outliers=outliers
    )
    db.add(validation)
    db.commit()
    db.refresh(validation)
    
    return {
        "id": validation.id,
        "dataset_id": dataset_id,
        "score": score,
        "total_issues": total_issues,
        "issues": {
            "missing_values": missing_values,
            "duplicate_rows": duplicate_rows,
            "type_errors": type_errors,
            "out_of_range": out_of_range,
            "invalid_patterns": invalid_patterns,
            "outliers": outliers
        },
        "details": {
            "total_cells": total_cells,
            "total_rows": len(df),
            "total_columns": len(df.columns)
        },
        "created_at": validation.created_at.isoformat()
    }

@app.get("/validate/{dataset_id}")
def get_validation(dataset_id: int, db: Session = Depends(get_db)):
    validation = db.query(Validation).filter(Validation.dataset_id == dataset_id).order_by(Validation.created_at.desc()).first()
    if not validation:
        raise HTTPException(status_code=404, detail="Validation not found")
    
    return {
        "id": validation.id,
        "dataset_id": validation.dataset_id,
        "score": validation.score,
        "total_issues": (
            validation.missing + 
            validation.duplicates + 
            validation.type_errors + 
            validation.out_of_range + 
            validation.invalid_patterns + 
            validation.outliers
        ),
        "issues": {
            "missing_values": validation.missing,
            "duplicate_rows": validation.duplicates,
            "type_errors": validation.type_errors,
            "out_of_range": validation.out_of_range,
            "invalid_patterns": validation.invalid_patterns,
            "outliers": validation.outliers
        },
        "details": {},
        "created_at": validation.created_at.isoformat()
    }
