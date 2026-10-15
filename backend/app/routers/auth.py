from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import get_current_user
from app.models import User
from app.schemas import TokenOut, UserCreate, UserLogin, UserOut
from app.security import (
    DUMMY_HASH,
    create_access_token,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])

DbSession = Annotated[Session, Depends(get_db)]


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: DbSession) -> User:
    if db.scalar(select(User).where(User.username == payload.username)):
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Username already registered")
    if db.scalar(select(User).where(User.email == payload.email)):
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Email already registered")

    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        # A concurrent request inserted the same username/email first.
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="Username or email already registered"
        )
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenOut)
def login(payload: UserLogin, db: DbSession) -> TokenOut:
    user = db.scalar(select(User).where(User.username == payload.username))

    # Always run one hash verification so timing is similar either way.
    hashed = user.hashed_password if user else DUMMY_HASH
    password_ok = verify_password(payload.password, hashed)

    if user is None or not password_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return TokenOut(access_token=create_access_token(user.id))


@router.get("/me", response_model=UserOut)
def me(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    return current_user