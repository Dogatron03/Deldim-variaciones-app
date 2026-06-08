import os
from datetime import timedelta, timezone, datetime
from typing import Annotated

from dotenv import load_dotenv

import jwt
from jwt.exceptions import InvalidTokenError

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware

from sqlmodel import Field, Session, SQLModel, create_engine, select

from pwdlib import PasswordHash
from pydantic import BaseModel

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
DATABASE_URL = os.getenv("DATABASE_URL")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not set in environment")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set in environment")

connect_args = {"check_same_thread": False}
engine = create_engine(DATABASE_URL, connect_args=connect_args)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

password_hash = PasswordHash.recommended()


def get_password_hash(password: str):
    return password_hash.hash(password)


def verify_password(plain_password, hashed_password):
    return password_hash.verify(plain_password, hashed_password)


app = FastAPI()

origins = [
    "http://localhost.tiangolo.com",
    "https://localhost.tiangolo.com",
    "http://localhost",
    "http://localhost:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class UserPublic(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserCreate(BaseModel):
    username: str
    password: str
    email: str | None = None
    full_name: str | None = None


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(index=True)
    email: str = Field(default=None)
    full_name: str = Field(default=None)
    disabled: bool = Field(default=False)
    password: str = Field(default=None)


def response_user_from_user(user: User) -> UserPublic:
    return UserPublic(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        disabled=user.disabled
    )


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_user(session: Session, username: str) -> User | None:
    statement = select(User).where(User.username == username)
    return session.exec(statement).first()


def authenticate_user(
        session: Session,
        username: str,
        password: str,
) -> User | None:
    user = get_user(session, username)

    if not user:
        return None

    if not verify_password(password, user.password):
        return None

    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + (
            expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    to_encode.update({"exp": expire})

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(
        token: Annotated[str, Depends(oauth2_scheme)],
        session: Annotated[Session, Depends(get_session)],
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")

        if username is None:
            raise credentials_exception

    except InvalidTokenError:
        raise credentials_exception

    user = get_user(session, username)

    if user is None:
        raise credentials_exception

    return user

async def get_current_active_user(
        current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")

    return current_user


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


@app.on_event("startup")
def on_startup():
    create_db_and_tables()


@app.post("/token", response_model=Token)
async def login(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
        session: Annotated[Session, Depends(get_session)],
):
    user = authenticate_user(
        session=session,
        username=form_data.username,
        password=form_data.password,
    )

    if not user:
        raise HTTPException(
            status_code=400,
            detail="Incorrect username or password",
        )

    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }

@app.post("/users", response_model=UserPublic)
def create_user(
        user_create: UserCreate,
        session: Annotated[Session, Depends(get_session)],
):
    existing_user = get_user(session, user_create.username)

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username already registered",
        )

    user = User(
        username=user_create.username,
        email=user_create.email,
        full_name=user_create.full_name,
        disabled=False,
        password=password_hash.hash(user_create.password),
    )

    session.add(user)
    session.commit()
    session.refresh(user)

    return response_user_from_user(user)


@app.get("/users/me", response_model=UserPublic)
async def read_users_me(
        current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user
