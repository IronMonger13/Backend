# ------------------------------------------------------------- LIBRARY IMPORTS -------------------------------------------------------------
from dotenv import load_dotenv
import os
from typing import Union, Any
from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, APIRouter
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext


# -------------------------------------------------------------- FILE IMPORTS --------------------------------------------------------------
from db import Users, Tokens, get_db
from models import Token_data, Refresh_token_request


# ----------------------------------------------------------- DEFINING CONSTANTS -----------------------------------------------------------
load_dotenv()
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day
ALGORITHM = "HS256"
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


# Getting details of current user
async def get_current_user(token: str = Depends(reusable_oauth), db=Depends(get_db)):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Token missing user_id")
        token_data = Token_data(username=username)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(Users).filter(Users.username == token_data.username).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# Refresh token to get new access token
@router.post("/refresh")
def refresh_token(
    request: Refresh_token_request, db=Depends(get_db)
):  # take refresh token as parameter
    try:
        # Decode incoming refresh token
        payload = jwt.decode(
            request.refresh_token, JWT_REFRESH_SECRET_KEY, algorithms=[ALGORITHM]
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

        return {"access_token": new_access_token}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
