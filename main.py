# -------------------------------------------------------------- FILE IMPORTS --------------------------------------------------------------
from models import Create_user, Get_user, Token_schema
from db import Users, Tokens, get_db
from auth import (
    create_access_token,
    create_refresh_token,
    get_current_user,
    pwd_context,
)
from auth import router as auth_router
from oauth_providers import oauth, google_authorize_redirect

# ------------------------------------------------------------- LIBRARY IMPORTS -------------------------------------------------------------
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv
import os


load_dotenv()

# -------------------------------------------------------- INITIALIZING FASTAPI APP --------------------------------------------------------
app = FastAPI()
app.include_router(auth_router)


# ---------------------------------------------------------------- ENDPOINTS ----------------------------------------------------------------
# Signup endpoint
@app.post("/signup/", response_model=Get_user)
def create_user(user_details: Create_user, db=Depends(get_db)):
    # Checking if username exists
    existing_user = (
        db.query(Users).filter(user_details.username == Users.username).first()
    )
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    # Converting user details into dict
    user_details = user_details.model_dump()

    # Hashing password
    user_details["hashed_password"] = pwd_context.hash(user_details.pop("password"))

    # storing in DB
    new_user = Users(**user_details)
    db.add(new_user)
    db.commit()
    return new_user


# Login endpoint (returns access token)
@app.post("/login/", response_model=Token_schema)
def user_login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db=Depends(get_db),
):
    # Checking is username exists in DB
    existing_user = db.query(Users).filter(Users.username == form_data.username).first()
    if not existing_user:
        raise HTTPException(status_code=404, detail="Invalid credentials")

    # Verifying password
    if not pwd_context.verify(form_data.password, existing_user.hashed_password):
        raise HTTPException(status_code=404, detail="Invalid credentials")

    # Generating access and refresh tokens
    new_access_token = create_access_token(existing_user.username)
    new_refresh_token = create_refresh_token(existing_user.username)

    # Storing tokens in db
    token_entry = Tokens(
        username=existing_user.username,
        access_token=new_access_token,
        refresh_token=new_refresh_token,
    )
    db.add(token_entry)
    db.commit()

    # Returning access and refresh token
    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
    }


# Get current user endpoint
@app.get("/me", response_model=Get_user)
async def get_me(user: Users = Depends(get_current_user)):
    return user


# Logout endpoint (takes away access and refresh tokens)
@app.post("/logout")
def user_logout(
    current_user=Depends(get_current_user),  # get currently logged in user
    db=Depends(get_db),
):
    # Fetch user's tokens fromn db
    user = db.query(Tokens).filter(Tokens.username == current_user.username).first()

    # delete tokens for user logging in via UI
    if user:
        db.delete(user)
        db.commit()

    return {"message": "Successfully logged out"}


# ------------------------------------------------- OAUTH 2: 3RD PARTY LOGIN IMPLEMENTATION -------------------------------------------------

app.add_middleware(SessionMiddleware, secret_key=os.getenv("MIDDLEWARE_SECRET_KEY"))


# Route to start google login
@app.get("/login/google")
async def login_google(request: Request):
    return await google_authorize_redirect(request)


# Callback route google redirects to
@app.get("/auth/callback")
async def auth_google_callback(request: Request, db=Depends(get_db)):
    # exchange received code for token and and get user info
    token = await oauth.google.authorize_access_token(request)  # fetch token

    # Get user info from token
    user_info = token["userinfo"]

    if user_info is None or "email" not in user_info:
        raise HTTPException(status_code=400, detail="Failed to obtain user info")

    # set user data for db
    email = user_info["email"]
    name = user_info.get("name", email.split("@")[0])
    username = name.replace(" ", "_")

    # Checking for user in db, if not create a new one
    db_user = db.query(Users).filter(Users.email == email).first()

    if not db_user:
        db_user = Users(
            name=name, age=0, email=email, username=username, hashed_password=""
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)

    # generating access and refresh tokens
    new_access_token = create_access_token(username)
    new_refresh_token = create_refresh_token(username)

    # Storing these tokes in DB
    token_entry = Tokens(
        username=username,
        access_token=new_access_token,
        refresh_token=new_refresh_token,
    )
    db.add(token_entry)
    db.commit()
    db.refresh(token_entry)

    # return json for these new tokens
    return JSONResponse(
        {"access_token": new_access_token, "refresh_token": new_refresh_token}
    )
