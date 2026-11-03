import logging
import traceback
from datetime import datetime
from typing import List, Optional

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

import models
from auth import create_access_token, get_current_user, get_password_hash, verify_password
from config import NOTIFY_SERVICE_URL, SHARE_BASE_URL
from database import engine, get_db, search_scans_by_query
from sharing import (
    MAX_FAILED_PASSWORD_ATTEMPTS,
    SHARE_LINK_TTL,
    generate_share_token,
    hash_share_token,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="VulnTracker API",
    description="Vulnerability tracking and management REST API",
    version="1.0.0",
)


@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    response = await call_next(request)
    origin = request.headers.get("origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "*"
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception on %s: %s", request.url, exc)
    return JSONResponse(
        status_code=500,
        content={
            "error": str(exc),
            "type": type(exc).__name__,
            "traceback": traceback.format_exc(),
            "path": str(request.url),
        },
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class UserRegister(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScanCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    cve_id: Optional[str] = None
    affected_component: str
    remediation_notes: Optional[str] = None


class ScanUpdate(BaseModel):
    status: Optional[str] = None
    remediation_notes: Optional[str] = None


class ScanOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    remediation_notes: Optional[str]
    owner_id: int
    created_at: datetime

    class Config:
        from_attributes = True


class ShareCreate(BaseModel):
    # bcrypt only uses the first 72 bytes, so cap the length instead of
    # silently truncating; the minimum blocks trivially guessable passwords.
    password: Optional[str] = Field(default=None, min_length=8, max_length=72)


class ShareOut(BaseModel):
    share_url: str


class SharedScanOut(BaseModel):
    """Public view of a scan. Deliberately omits owner_id and other internals."""
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    remediation_notes: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fire_notify(event: str, payload: dict) -> None:
    try:
        httpx.post(
            f"{NOTIFY_SERVICE_URL}/notify",
            json={"event": event, "payload": payload},
            timeout=5.0,
        )
    except Exception as exc:
        logger.warning("Notification service unreachable: %s", exc)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: UserRegister, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(models.User).filter(models.User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = models.User(
        username=payload.username,
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login")
def login(payload: UserLogin, db: Session = Depends(get_db)):
    logger.info("Login attempt — username: %s password: %s", payload.username, payload.password)
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        logger.warning(
            "Failed login — username: '%s' password: '%s'",
            payload.username,
            payload.password,
        )
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# Scan routes
# ---------------------------------------------------------------------------

@app.get("/scans", response_model=List[ScanOut])
def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    return (
        db.query(models.ScanResult)
        .filter(models.ScanResult.owner_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .all()
    )


@app.post("/scans", response_model=ScanOut, status_code=201)
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if payload.severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(status_code=400, detail="severity must be critical | high | medium | low")
    scan = models.ScanResult(**payload.model_dump(), owner_id=current_user.id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.created", {
        "id": scan.id,
        "title": scan.title,
        "severity": scan.severity,
        "owner": current_user.username,
    })
    return scan


@app.get("/scans/search")
def search_scans(
    q: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if not q or len(q) < 2:
        raise HTTPException(status_code=400, detail="Search query must be at least 2 characters")
    results = search_scans_by_query(db, q)
    return {"results": results, "count": len(results)}


@app.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(models.ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.patch("/scans/{scan_id}", response_model=ScanOut)
def update_scan(
    scan_id: int,
    payload: ScanUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if payload.status is not None:
        if payload.status not in ("open", "in_progress", "resolved"):
            raise HTTPException(status_code=400, detail="status must be open | in_progress | resolved")
        scan.status = payload.status
    if payload.remediation_notes is not None:
        scan.remediation_notes = payload.remediation_notes
    scan.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.updated", {
        "id": scan.id,
        "title": scan.title,
        "status": scan.status,
        "owner": current_user.username,
    })
    return scan


@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()


# ---------------------------------------------------------------------------
# Shared report links
# ---------------------------------------------------------------------------

@app.post("/scans/{scan_id}/share", response_model=ShareOut, status_code=201)
def create_share_link(
    scan_id: int,
    payload: Optional[ShareCreate] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # Only the scan's owner may share it. Filtering on owner_id (rather than
    # fetching by id and comparing) means a non-owner gets the same 404 as a
    # missing scan, so scan ids cannot be enumerated.
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    token = generate_share_token()
    password = payload.password if payload else None
    link = models.ShareLink(
        token_hash=hash_share_token(token),
        scan_id=scan.id,
        created_by=current_user.id,
        password_hash=get_password_hash(password) if password else None,
        expires_at=datetime.utcnow() + SHARE_LINK_TTL,
    )
    db.add(link)
    db.commit()
    # The raw token exists only in this response; it cannot be recovered later.
    return {"share_url": f"{SHARE_BASE_URL}/share/{token}"}


@app.get("/share/{token}", response_model=SharedScanOut)
def get_shared_scan(
    token: str,
    response: Response,
    password: Optional[str] = None,
    db: Session = Depends(get_db),
):
    # Never cache a shared report in browsers or intermediary proxies.
    response.headers["Cache-Control"] = "no-store"

    link = db.query(models.ShareLink).filter(
        models.ShareLink.token_hash == hash_share_token(token)
    ).first()
    # Unknown, malformed and expired tokens all return the same 404 so the
    # response does not reveal whether a token ever existed.
    if not link or link.expires_at <= datetime.utcnow():
        raise HTTPException(status_code=404, detail="Share link not found or expired")

    if link.password_hash:
        if link.failed_attempts >= MAX_FAILED_PASSWORD_ATTEMPTS:
            raise HTTPException(status_code=429, detail="Too many failed attempts for this link")
        if not password:
            raise HTTPException(status_code=401, detail="Password required")
        if not verify_password(password, link.password_hash):
            link.failed_attempts += 1
            db.commit()
            raise HTTPException(status_code=401, detail="Invalid password")

    return link.scan


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "vulntracker-api"}
