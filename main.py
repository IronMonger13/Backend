# -------------------------------------------------------------- FILE IMPORTS --------------------------------------------------------------
from models import Create_user, Get_user, Token_schema
from db import Users, Tokens, get_db
from auth import (
    create_access_token,
    create_refresh_token,
    get_current_user,
    pwd_context,
)
from auth import router as auth_router, reusable_oauth


# ------------------------------------------------------------- LIBRARY IMPORTS -------------------------------------------------------------
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm


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
    token: str = Depends(reusable_oauth),  # get current user's token
    db=Depends(get_db),
):
    # Fetch user's token
    token_to_delete = db.query(Tokens).filter(Tokens.access_token == token).first()

    # Check if user has tokens already or not
    if not token_to_delete:
        raise HTTPException(status_code=404, detail="No valid token found")

    # Delete the token
    db.delete(token_to_delete)
    db.commit()
    return {"message": "Successfully logged out"}
