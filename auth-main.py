from datetime import datetime, timedelta
from typing import Annotated, Union
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import pdb
import sqlite3


# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30


con = sqlite3.connect("testDB.db",check_same_thread=False)
cur = con.cursor()
users = cur.execute("select * from users").fetchall()


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    fullname: Union[str, None] = None
    tc_id: Union[str,None] = None
    cc_number: Union[str,None] = None
    status: Union[str,None] = None
    roleid: Union[str,None] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    for user_obj in db:
        if username in user_obj:
            tempObj = {
                "username": user_obj[1],
                "fullname": user_obj[2],
                "email": user_obj[3],
                "hashed_password": user_obj[4],
                'tc_id': user_obj[5],
                'cc_number': user_obj[6],
                'status': user_obj[7],
                'roleid': str(user_obj[9])
            }
            return UserInDB(**tempObj)


def authenticate_user(users, username: str, password: str):
    user = get_user(users, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(user, data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    expire_timestamp = datetime.timestamp(expire)
    now_timestamp = datetime.now().timestamp()
    if expire_timestamp > now_timestamp:
        try:
            cur.execute('UPDATE users SET status = ? WHERE email = ?', ('enabled', user.email))
            con.commit()
        except Exception as e:
            conn.rollback()
            raise HTTPException(status_code=500, detail="Veritabanı güncellemesi sırasında bir hata oluştu.")
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(users, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

def update_user(username: str, fullname: str, email: str):
    try:
        cur.execute('UPDATE users SET username = ?, fullname = ? WHERE email = ?', (username, fullname, email))
        con.commit()
        return True
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail="Veritabanı güncellemesi sırasında bir hata oluştu.")


async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]):
    if current_user is None:
        raise HTTPException(status_code=400, detail="Kullanıcı Bulunamadı")
    if current_user.status == 'disabled': 
        raise HTTPException(status_code=400, detail="Inaktif Kullanıcı")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_user(users, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    access_token = create_access_token(
        user,data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user

@app.put("/users/me/edit", response_model=User)
async def edit_user(current_user: Annotated[User, Depends(get_current_active_user)],username: str | None = None,fullname: str | None = None):
    edit_username = current_user.username if username is None else username 
    edit_fullname = current_user.fullname if fullname is None else fullname
    success = update_user(edit_username, edit_fullname, current_user.email)
    if not success:
        raise HTTPException(status_code=500, detail="Kullanıcı güncellemesi sırasında bir hata oluştu.")
    edited_user = {
        'username': edit_username,
        'fullname': edit_fullname,
        'email': current_user.email,
        'tc_id': current_user.tc_id,
        'cc_number': current_user.cc_number,
        'status': current_user.status,
        'roleid': current_user.roleid
    }
    return edited_user

@app.delete("/users/{user_id}/")
async def read_users_me(user_id: int, current_user: Annotated[User, Depends(get_current_active_user)]):
    if current_user.roleid != '1':
        raise HTTPException(status_code=400, detail="Yetkiniz bulunmamaktadır.")
    if current_user.roleid == '1' and current_user.status != "enabled":
        raise HTTPException(status_code=400, detail="Kullanıcı aktif degil.")
    try:
        cur.execute(f'delete from users where userid={int(user_id)}')
        con.commit()
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail="Veritabanı güncellemesi sırasında bir hata oluştu.")
    return {'detail': 'Kullanıcı silindi.'}


@app.get("/users/me/items/")
async def read_own_items(current_user: Annotated[User, Depends(get_current_active_user)]):
    return [{"item_id": "Foo", "owner": current_user.username}]