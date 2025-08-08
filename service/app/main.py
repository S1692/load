import os
import json
import logging
from datetime import datetime
from typing import Optional, List

from fastapi import FastAPI, Request, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from sqlalchemy import create_engine, String, DateTime, func
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Mapped, mapped_column, Session
from sqlalchemy.exc import IntegrityError

# Optional: load .env if present (local dev). In Railway, envs are injected.
try:
    from dotenv import load_dotenv  # python-dotenv
    # Adjust the path to point to the root .env file
    dotenv_path = os.path.join(os.path.dirname(__file__), '..', '..', '.env')
    if os.path.exists(dotenv_path):
        load_dotenv(dotenv_path=dotenv_path)
except Exception:
    pass

# ----------------------------------------------------------------------------
# Logging setup
# ----------------------------------------------------------------------------
logger = logging.getLogger("user-service")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    class EmojiFormatter(logging.Formatter):
        def format(self, record):
            log_message = super().format(record)
            if "request" in record.msg: return f"➡️  {log_message}"
            if "response" in record.msg: return f"⬅️  {log_message}"
            if "db" in record.msg: return f"🗄️  {log_message}"
            return f"ℹ️  {log_message}"
    handler.setFormatter(EmojiFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)

def log_event(event: str, **kwargs):
    parts = [f"event='{event}'"]
    for k, v in kwargs.items():
        parts.append(f"{k}='{v}'")
    logger.info(" ".join(parts))

# ----------------------------------------------------------------------------
# Database setup
# ----------------------------------------------------------------------------
def normalize_db_url(url: Optional[str]) -> Optional[str]:
    if not url: return url
    if url.startswith("postgres://"): url = url.replace("postgres://", "postgresql://", 1)
    if url.startswith("postgresql+asyncpg://"): url = url.replace("postgresql+asyncpg://", "postgresql+psycopg2://", 1)
    return url

DATABASE_URL = normalize_db_url(os.getenv("DATABASE_URL"))
if not DATABASE_URL:
    log_event("config.db.missing", message="DATABASE_URL is not set; DB features disabled")

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), default=datetime.utcnow, nullable=False)

engine = create_engine(DATABASE_URL) if DATABASE_URL else None
SessionLocal = sessionmaker(bind=engine) if engine else None

# ----------------------------------------------------------------------------
# Security helpers
# ----------------------------------------------------------------------------
import hashlib
import secrets

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"{salt.hex()}${dk.hex()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split("$")
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        return secrets.compare_digest(dk, expected)
    except Exception:
        return False

# ----------------------------------------------------------------------------
# FastAPI app
# ----------------------------------------------------------------------------
app = FastAPI(title="User Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    if engine:
        Base.metadata.create_all(engine)
        log_event("startup", message="DB initialized and tables ensured")
    else:
        log_event("startup.no_db", message="Running without database")

def get_db() -> Session:
    if not SessionLocal:
        raise HTTPException(status_code=500, detail="Database not configured")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ----------------------------------------------------------------------------
# Schemas
# ----------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    username: str
    password: str
    email: EmailStr
    full_name: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    full_name: Optional[str]
    created_at: datetime
    class Config:
        from_attributes = True

def mask_sensitive(d: dict) -> dict:
    masked = dict(d)
    if "password" in masked: masked["password"] = "*****"
    if "password_hash" in masked: masked["password_hash"] = "***hash***"
    return masked

# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
@app.post("/register")
async def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    log_event("request.register", body=mask_sensitive(payload.model_dump()))
    exists = db.query(User).filter(User.username == payload.username).first()
    if exists:
        log_event("db.user.duplicate", username=payload.username)
        raise HTTPException(status_code=409, detail="Username already exists")
    
    user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError as e:
        db.rollback()
        log_event("db.commit.error", error=str(e))
        raise HTTPException(status_code=400, detail="Could not create user")
    db.refresh(user)
    log_event("db.user.created", user_id=user.id)
    return {"message": "User created successfully", "user": UserOut.model_validate(user).model_dump()}

@app.post("/login")
async def login(payload: LoginRequest, db: Session = Depends(get_db)):
    log_event("request.login", body=mask_sensitive(payload.model_dump()))
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        log_event("auth.login.fail", username=payload.username)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    log_event("auth.login.success", user_id=user.id)
    return {"message": "Login successful", "user": UserOut.model_validate(user).model_dump()}

@app.get("/check-username")
async def check_username(username: str = Query(..., min_length=1), db: Session = Depends(get_db)):
    exists = db.query(User.id).filter(User.username == username).first() is not None
    log_event("request.check_username", username=username, exists=exists)
    return {"exists": exists}

@app.get("/users", response_model=dict)
async def list_users(db: Session = Depends(get_db)):
    rows: List[User] = db.query(User).order_by(User.created_at.desc()).all()
    users = [UserOut.model_validate(u).model_dump() for u in rows]
    log_event("request.users", count=len(users))
    return {"users": users}

@app.get("/health")
async def health():
    log_event("health.check")
    return {"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}
