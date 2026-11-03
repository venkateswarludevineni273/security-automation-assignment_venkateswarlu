import logging
from datetime import datetime
from typing import List, Optional

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import update
from sqlalchemy.orm import Session

import models
from auth import create_access_token, get_current_user, get_password_hash, verify_password
from config import CORS_ALLOWED_ORIGINS, NOTIFY_SERVICE_URL, SHARE_BASE_URL
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


# Cross-origin access is opt-in via CORS_ALLOWED_ORIGINS. The API authenticates
# with a bearer header (no cookies), so credentials are never allowed.
if CORS_ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ALLOWED_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Full detail goes to the server log only; the client gets nothing useful
    # to an attacker (no stack trace, exception text, or internal paths).
    logger.error("Unhandled exception on %s %s", request.method, request.url.path, exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


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
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        logger.warning("Failed login for username %r", payload.username)
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
    results = search_scans_by_query(db, q, current_user.id)
    return {"results": results, "count": len(results)}


@app.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
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
    x_share_password: Optional[str] = Header(default=None),
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
        # The X-Share-Password header is preferred: query strings end up in
        # access logs, proxies and browser history. ?password= is still
        # accepted because the assignment specifies it.
        supplied = x_share_password or password
        if not supplied:
            raise HTTPException(status_code=401, detail="Password required")

        # Reserve an attempt *atomically* before checking the password. A
        # read-then-write counter can be raced: N parallel requests all read
        # "0 failures" and all get a guess. The conditional UPDATE lets at
        # most MAX_FAILED_PASSWORD_ATTEMPTS requests through in total.
        reserved = db.execute(
            update(models.ShareLink)
            .where(
                models.ShareLink.id == link.id,
                models.ShareLink.failed_attempts < MAX_FAILED_PASSWORD_ATTEMPTS,
            )
            .values(failed_attempts=models.ShareLink.failed_attempts + 1)
        ).rowcount
        db.commit()
        if reserved == 0:
            raise HTTPException(status_code=429, detail="Too many failed attempts for this link")

        if not verify_password(supplied, link.password_hash):
            raise HTTPException(status_code=401, detail="Invalid password")

        # Correct password: give the attempt back.
        db.execute(
            update(models.ShareLink)
            .where(models.ShareLink.id == link.id)
            .values(failed_attempts=0)
        )
        db.commit()

    return link.scan


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "vulntracker-api"}
