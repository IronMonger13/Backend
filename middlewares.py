# ------------------------------------------------------------- LIBRARY IMPORTS -------------------------------------------------------------
import time
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from jose import jwt, JWTError
from dotenv import load_dotenv
import os


# -------------------------------------------------------------- FILE IMPORTS --------------------------------------------------------------
from db import get_db, Users


# ----------------------------------------------------------- DEFINING CONSTANTS -----------------------------------------------------------
load_dotenv()
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")


# --------------------------------------------------------------- MIDDLEWARES ---------------------------------------------------------------
# Request time count middleware
class Add_process_time_header(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.perf_counter()
        response = await call_next(request)
        process_time = time.perf_counter() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        return response


# Authentication Middleware
class Verify_user(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            # Routes that should not require login
            public_paths = [
                "/login",
                "/signup",
                "/auth",
                "/docs",
                "/openapi.json",
                "/upload_files",
            ]

            # If request starts with these paths, skip them
            if any(request.url.path.startswith(path) for path in public_paths):
                return await call_next(request)

            # Get access token from cookies
            token = request.cookies.get("access_token")
            if not token:
                raise HTTPException(status_code=401, detail="Unauthorized")

            # Decoding the token
            try:
                payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
                username = payload.get("sub")
                if not username:
                    raise HTTPException(status_code=401, detail="Invalid token payload")
            except JWTError:
                raise HTTPException(status_code=401, detail="Invalid or expired token")

            # Fetch user from db
            gen = get_db()
            db = next(gen)
            try:
                user = db.query(Users).filter(Users.username == username).first()
                if not user:
                    raise HTTPException(status_code=401, detail="User not found")

                # Attach user to request
                request.state.user = user
            finally:
                db.close()

            # Pass to the next function or route
            response = await call_next(request)
            return response
        # Known HTTP Exceptions
        except HTTPException as e:
            return JSONResponse(status_code=e.status_code, content={"detail": e.detail})
        # Unknown Exceptions
        except Exception as e:
            return JSONResponse(status_code=500, content={"detail": str(e)})
