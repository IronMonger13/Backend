# ------------------------------------------------------------- LIBRARY IMPORTS -------------------------------------------------------------
from dotenv import load_dotenv
import os
from typing import Union, Any, Annotated
from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, APIRouter, Cookie, Response
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext


# -------------------------------------------------------------- FILE IMPORTS --------------------------------------------------------------
from db import Users, Tokens, get_db
from models import Token_data


# ----------------------------------------------------------- DEFINING CONSTANTS -----------------------------------------------------------
load_dotenv()
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day
ALGORITHM = os.getenv("ALGORITHM")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_REFRESH_SECRET_KEY = os.getenv("JWT_REFRESH_SECRET_KEY")


# ---------------------------------------------------------- CREATING AUTH ROUTES ----------------------------------------------------------
router = APIRouter(prefix="/auth")


# ---------------------------------------------------- CREATING PASSWORD HASHING CONTEXT ----------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# --------------------------------------------------------- TOKEN REUSABILITY SETUP ---------------------------------------------------------
reusable_oauth = OAuth2PasswordBearer(tokenUrl="/login")


# ------------------------------------------------------------ HELPER FUNCTIONS ------------------------------------------------------------
# Generating access token
def create_access_token(subject: Union[str, Any], expires_delta: int = None):
    if expires_delta is not None:  # means token has not expired yet
        expires_delta = datetime.utcnow() + expires_delta
    else:  # token is expired
        expires_delta = datetime.utcnow() + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )

    # Defining payload data
    to_encode = {"exp": expires_delta, "sub": str(subject), "type": "access"}

    # Encoding to create access token
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, ALGORITHM)
    return encoded_jwt


# Generating refresh token
def create_refresh_token(subject: Union[str, Any], expires_delta: int = None):
    if expires_delta is not None:  # means token has not expired yet
        expires_delta = datetime.utcnow() + expires_delta
    else:  # token is expired
        expires_delta = datetime.utcnow() + timedelta(
            minutes=REFRESH_TOKEN_EXPIRE_MINUTES
        )

    # Defining payload data
    to_encode = {"exp": expires_delta, "sub": str(subject), "type": "refresh"}

    # Encoding to create refresh token
    encoded_jwt_refresh = jwt.encode(to_encode, JWT_REFRESH_SECRET_KEY, ALGORITHM)
    return encoded_jwt_refresh


# Refresh token to get new access token
@router.post("/refresh")
def refresh_token(
    response: Response,
    refresh_token: Annotated[str | None, Cookie()] = None,
    db=Depends(get_db),
):
    # Verifying cookie contains refresh token
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Decoding token
    try:
        payload = jwt.decode(
            refresh_token, JWT_REFRESH_SECRET_KEY, algorithms=[ALGORITHM]
        )

        # Check if username exists in payload or not
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        # Generate new token
        new_access_token = create_access_token(username)

        # Update this new token in DB
        token_data = db.query(Tokens).filter(Tokens.username == username).first()
        token_data.access_token = new_access_token
        db.commit()

        # Storing new access token in cookie
        response.set_cookie(
            key="access_token",
            value=new_access_token,
            httponly=True,
            samesite="strict",
            max_age=900,  # 15 minutes
            path="/",
        )

        return {"message": "Access token refreshed"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
