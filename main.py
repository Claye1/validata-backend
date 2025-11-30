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
Base.metadata.drop_all(bind=engine)
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
        
        csv_text = contents.decode('utf-8')
        
        new_dataset = Dataset(
            filename=file.filename,
            rows=len(df),
            columns=",".join(df.columns.tolist()),
            csv_data=csv_text
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
            if any(keyword in col.lower() for keyword in ['email', 'mail', 'e-mail']):
                email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                invalid_patterns += int((~df[col].astype(str).str.match(email_pattern, na=False)).sum())
    
    # 6. Outliers
    outliers = 0
    for col in df.select_dtypes(include=['int64', 'float64']).columns:
        mean = df[col].mean()
        std = df[col].std()
        if std > 0:
            z_scores = (df[col] - mean) / std
            outliers += int((abs(z_scores) > 3).sum())
    
    total_cells = len(df) * len(df.columns)
    total_issues = missing_values + duplicate_rows + type_errors + out_of_range + invalid_patterns + outliers
    
    if total_cells > 0:
        score = max(0, 100 - int((total_issues / total_cells) * 100))
    else:
        score = 0
    
    new_validation = Validation(
        dataset_id=dataset_id,
        score=score,
        missing=missing_values,
        duplicates=duplicate_rows,
        type_errors=type_errors,
        out_of_range=out_of_range,
        invalid_patterns=invalid_patterns,
        outliers=outliers
    )
    db.add(new_validation)
    db.commit()
    db.refresh(new_validation)
    
    issues = {
        "missing_values": missing_values,
        "duplicate_rows": duplicate_rows,
        "type_errors": type_errors,
        "out_of_range": out_of_range,
        "invalid_patterns": invalid_patterns,
        "outliers": outliers
    }
    
    return {
        "dataset_id": dataset_id,
        "score": score,
        "issues": issues,
        "total_issues": total_issues,
        "created_at": new_validation.created_at.isoformat(),
        "details": {
            "missing_values": {
                "count": missing_values,
                "severity": "high",
                "description": "Empty cells found in critical columns"
            },
            "duplicate_rows": {
                "count": duplicate_rows,
                "severity": "medium",
                "description": "Exact duplicate records detected"
            },
            "type_errors": {
                "count": type_errors,
                "severity": "high",
                "description": "Data type mismatches (e.g., text in numeric fields)"
            },
            "out_of_range": {
                "count": out_of_range,
                "severity": "medium",
                "description": "Values outside expected ranges"
            },
            "invalid_patterns": {
                "count": invalid_patterns,
                "severity": "low",
                "description": "Format validation failures (emails, dates, etc.)"
            },
            "outliers": {
                "count": outliers,
                "severity": "low",
                "description": "Statistical anomalies detected"
            }
        }
    }

@app.get("/validate/{dataset_id}")
def get_validation(dataset_id: int, db: Session = Depends(get_db)):
    validation = db.query(Validation).filter(Validation.dataset_id == dataset_id).first()
    if not validation:
        raise HTTPException(status_code=404, detail="Validation not found")
    
    issues = {
        "missing_values": validation.missing,
        "duplicate_rows": validation.duplicates,
        "type_errors": validation.type_errors,
        "out_of_range": validation.out_of_range,
        "invalid_patterns": validation.invalid_patterns,
        "outliers": validation.outliers
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