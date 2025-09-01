# ------------------------------------------------------------- LIBRARY IMPORTS -------------------------------------------------------------
from dotenv import load_dotenv
import os
from sqlalchemy import Column, Integer, String, create_engine, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship


# -------------------------------------------------------- GETTING CONNECTION STRING --------------------------------------------------------
load_dotenv()
connection_string = os.getenv("postgres_uri")
engine = create_engine(connection_string, echo=True)


# ---------------------------------------------------------- BASE CLASS FOR MODELS ----------------------------------------------------------
Base = declarative_base()


# ------------------------------------------------------------- DEFINING TABLES -------------------------------------------------------------
# Users table
class Users(Base):
    __tablename__ = "users"
    user_id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    age = Column(Integer, nullable=False)
    username = Column(String, nullable=False, unique=True)
    hashed_password = Column(String, nullable=False)

    # relationship of users and tokens
    # users = relationship("Tokens", back_populates="tokens")


# Tokens table
class Tokens(Base):
    __tablename__ = "tokens"
    token_id = Column(Integer, primary_key=True)
    access_token = Column(String, nullable=False)
    refresh_token = Column(String, nullable=False)
    username = Column(String, ForeignKey("users.username"), nullable=False)

    # relationship of users and tokens
    tokens = relationship("Users")


# ----------------------------------------------- CREATING TABLES IF THEY DONT ALREADY EXIST -----------------------------------------------
Base.metadata.create_all(bind=engine)


# ------------------------------------------------------------- SESSION FACTORY -------------------------------------------------------------
session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)


# -------------------------------------------------------- DEPENDENCY FOR API ROUTES --------------------------------------------------------
def get_db():
    db = session_local()
    try:
        yield db
    finally:
        db.close()
