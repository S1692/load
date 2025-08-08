, gateway import os
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
    load_dotenv()
except Exception:
    pass

# ----------------------------------------------------------------------------
# Logging setup: emit structured JSON logs for every request and DB action
# ----------------------------------------------------------------------------
logger = logging.getLogger("gateway")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    # Use a custom formatter for colorful, emoji-filled logs
    class EmojiFormatter(logging.Formatter):
        def format(self, record):
            log_message = super().format(record)
            # a simple way to distinguish log messages, we can extend this
            if "request" in record.msg:
                return f"➡️  {log_message}"
            if "response" in record.msg:
                return f"⬅️  {log_message}"
            if "db" in record.msg:
                return f"🗄️  {log_message}"
            return f"ℹ️  {log_message}"
    handler.setFormatter(EmojiFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)


def log_event(event: str, **kwargs):
    # The original structured logging is preserved, but we will log human-readable messages
    # This is a simple way to achieve both, a more robust solution could involve
    # custom handlers or processors
    
    # Construct a human-readable message
    parts = [f"event='{event}'"]
    for k, v in kwargs.items():
        parts.append(f"{k}='{v}'")
    
    # Log the human-readable message
    logger.info(" ".join(parts))
    
    # The original structured log payload
    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "service": os.getenv("SERVICE_NAME", "gateway"),
        "event": event,
        "railway": bool(os.getenv("RAILWAY_ENVIRONMENT", "").strip().lower() in {"1", "true", "yes"}),
        **kwargs,
    }
    # To avoid duplicate logs with the new formatter, we can either disable
    # the structured log, or use a different logger for it. For now, we will
    # comment it out to favor the new fancy logs.
    # logger.info(json.dumps(payload, ensure_ascii=False))


# ----------------------------------------------------------------------------
# Database setup (SQLAlchemy, PostgreSQL on Railway)
# ----------------------------------------------------------------------------

def normalize_db_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return url
    # Convert deprecated postgres:// to postgresql://
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    # If async driver is provided but our app uses sync psycopg2, normalize it
    if url.startswith("postgresql+asyncpg://"):
        url = url.replace("postgresql+asyncpg://", "postgresql+psycopg2://", 1)
    return url


DATABASE_URL = normalize_db_url(os.getenv("DATABASE_URL"))
if not DATABASE_URL:
    # Allow running without DB for local UI/testing, but warn via logs
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
# Security helpers (PBKDF2 from Python stdlib)
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
# FastAPI app and middleware
# ----------------------------------------------------------------------------
app = FastAPI(title="Gateway Service")

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
        log_event("startup.no_db", message="Running without database (DATABASE_URL missing)")


# Dependency to get DB session per request

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


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def mask_sensitive(d: dict) -> dict:
    masked = dict(d)
    if "password" in masked:
        masked["password"] = "*****"
    if "password_hash" in masked:
        masked["password_hash"] = "***hash***"
    return masked


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
@app.post("/register")
async def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    clean = payload.model_dump()
    log_event("request.register", body=mask_sensitive(clean))
    log_event("➡️ 收到註冊請求", username=payload.username)

    # Check duplicate username
    exists = db.query(User).filter(User.username == payload.username).first()
    if exists:
        log_event("db.user.duplicate", username=payload.username)
        log_event("❌ 用戶名重複", username=payload.username)
        raise HTTPException(status_code=409, detail="이미 존재하는 아이디입니다.")

    log_event("🔒 正在加密密碼...")
    user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
    )
    log_event("➕ 正在將用戶添加到資料庫...")
    db.add(user)
    try:
        db.commit()
        log_event("✅ 資料庫提交成功")
    except IntegrityError as e:
        db.rollback()
        log_event("db.commit.error", error=str(e))
        log_event("❌ 資料庫提交失敗", error=str(e))
        raise HTTPException(status_code=400, detail="사용자 생성 중 오류가 발생했습니다.")
    db.refresh(user)

    log_event("db.user.created", user={
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "created_at": user.created_at.isoformat(),
    })
    log_event("✅ 用戶創建成功", username=user.username)

    return {"message": "회원가입 성공", "user": UserOut.model_validate(user).model_dump()}


@app.post("/login")
async def login(payload: LoginRequest, db: Session = Depends(get_db)):
    clean = payload.model_dump()
    log_event("request.login", body=mask_sensitive(clean))
    log_event("➡️ 收到登入請求", username=payload.username)

    user = db.query(User).filter(User.username == payload.username).first()
    if not user:
        log_event("auth.login.fail", reason="user_not_found", username=payload.username)
        log_event("❌ 登入失敗：找不到用戶", username=payload.username)
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다.")

    log_event("🔑 正在驗證密碼...")
    if not verify_password(payload.password, user.password_hash):
        log_event("auth.login.fail", reason="bad_password", username=payload.username)
        log_event("❌ 登入失敗：密碼錯誤", username=payload.username)
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다.")

    log_event("auth.login.success", user_id=user.id, username=user.username)
    log_event("✅ 登入成功", username=user.username)
    return {"message": "로그인 성공", "user": UserOut.model_validate(user).model_dump()}


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


# Health check
@app.get("/health")
async def health():
    log_event("health.check")
    return {"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}
