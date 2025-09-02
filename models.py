from pydantic import BaseModel


# -------------------------------------------------------------- USER SCHEMAS --------------------------------------------------------------
# Base schema
class User_base_model(BaseModel):
    name: str
    age: int
    username: str
    email: str


# Creating user
class Create_user(User_base_model):
    password: str


# Retrieving user
class Get_user(User_base_model):
    user_id: int


# -------------------------------------------------------------- TOKEN SCHEMAS --------------------------------------------------------------
# Tokens validation
class Token_schema(BaseModel):
    access_token: str
    refresh_token: str


# Token data validation
class Token_data(BaseModel):
    username: str


# Schema to validate refresh token (to give new access token)
class Refresh_token_request(BaseModel):
    refresh_token: str
