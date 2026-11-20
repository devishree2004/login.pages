import os
import re

from dotenv import load_dotenv

from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from starlette.middleware.sessions import SessionMiddleware

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from database import Base, engine, get_db
from models import User
from security import hash_password, verify_password

load_dotenv()

SECRET_KEY = os.getenv("SESSION_SECRET")

if not SECRET_KEY:
    raise RuntimeError("SESSION_SECRET is missing in .env")


Base.metadata.create_all(bind=engine)


app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    same_site="lax",
    https_only=False
)

templates = Jinja2Templates(directory="templates")


def get_current_user(
    request: Request,
    db: Session = Depends(get_db)
):

    user_id = request.session.get("user_id")

    if not user_id:
        return None

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if user is None:
        request.session.clear()

    return user


@app.get("/", response_class=HTMLResponse)
def home(
    request: Request,
    user: User = Depends(get_current_user)
):

    return templates.TemplateResponse(
        request=request,
        name="home.html",
        context={"user": user}
    )



@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={"error": None}
    )

@app.post("/register")
def register_user(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):

    name = name.strip()
    email = email.strip().lower()

    error = None

    if not name or not email or not password:
        error = "All fields are required."

    elif len(name) > 100:
        error = "Name must be under 100 characters."

    elif not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        email
    ):
        error = "Enter a valid email address."

    elif len(password) < 8:
        error = "Password must contain at least 8 characters."

    elif len(password.encode("utf-8")) > 1024:
        error = "Password is too long."

    elif db.query(User).filter(
        User.email == email
    ).first():
        error = "Email already registered."

    if error:

        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": error},
            status_code=400
        )

    new_user = User(
        name=name,
        email=email,
        password_hash=hash_password(password),
        role="student"
    )

    db.add(new_user)

    try:
        db.commit()

    except IntegrityError:
        db.rollback()

        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={
                "error": "Email already registered."
            },
            status_code=400
        )

    return RedirectResponse(
        url="/login?registered=1",
        status_code=303
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(
    request: Request,
    registered: int = 0
):

    message = None

    if registered == 1:
        message = "Registration successful. Please login."

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": None,
            "message": message
        }
    )

@app.post("/login")
def login_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):

    email = email.strip().lower()

    user = db.query(User).filter(
        User.email == email
    ).first()

    if not user or not verify_password(
        password,
        user.password_hash
    ):

        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "Invalid email or password.",
                "message": None
            },
            status_code=401
        )


    request.session.clear()
    request.session["user_id"] = user.id

    return RedirectResponse(
        url="/dashboard",
        status_code=303
    )


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    user: User = Depends(get_current_user)
):

    if user is None:

        return RedirectResponse(
            url="/login",
            status_code=303
        )

    return templates.TemplateResponse(
        request=request,
        name="dash.html",
        context={"user": user}
    )

@app.post("/logout")
def logout(request: Request):

    request.session.clear()

    return RedirectResponse(
        url="/",
        status_code=303
    )