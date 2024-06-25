import os
import firebase_admin
from firebase_admin import credentials, auth, firestore
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from pydantic import BaseModel, EmailStr, Field
import requests

load_dotenv()

firebase_credentials = {
    "type": "service_account",
    "project_id": os.getenv("PROJECT_ID"),
    "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
    "private_key": os.getenv("FIREBASE_PRIVATE_KEY"),
    "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
    "client_id": os.getenv("FIREBASE_CLIENT_ID"),
    "auth_uri": os.getenv("FIREBASE_AUTH_URI"),
    "token_uri": os.getenv("FIREBASE_TOKEN_URI"),
    "auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_CERT_URL"),
    "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_CERT_URL")
}

cred = credentials.Certificate(firebase_credentials)
firebase_admin.initialize_app(cred)

app = FastAPI()
token_auth_scheme = HTTPBearer()
db = firestore.client()

class UserSignup(BaseModel):
    email: EmailStr
    password: str
    display_name: str = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserInfo(BaseModel):
    email: EmailStr
    password: str
    apiKey: str = Field(None, alias="apiKey")
    sheet: str = Field(None, alias="sheet")
    sheet_two: str = Field(None, alias="sheet_two")
    name: str = Field(None, alias="name")
    send_to: EmailStr = Field(None, alias="send_to")

class SendInfo(BaseModel):
    send_to: EmailStr = Field(None, alias="send_to")

def verify_token(auth: HTTPAuthorizationCredentials = Depends(token_auth_scheme)):
    try:
        decoded_token = auth.verify_id_token(auth.credentials)
        return decoded_token
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

@app.post("/signup")
async def signup(user_signup: UserSignup):
    try:
        user = auth.create_user(
            email=user_signup.email,
            password=user_signup.password,
            display_name=user_signup.display_name
        )
        return {
            "message": "Successfully created user",
            "uid": user.uid,
            "email": user.email
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/login")
async def login(user_login: UserLogin):
    try:
        user = auth.get_user_by_email(user_login.email)
        custom_token = auth.create_custom_token(user.uid)
        
        return {
            "message": "Successfully logged in",
            "uid": user.uid,
            "custom_token": custom_token.decode() 
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/protected")
def read_protected_data(decoded_token: dict = Depends(verify_token)):
    uid = decoded_token['uid']
    return {"message": "Protected data", "user_id": uid}

@app.post("/demo")
def run_pipeline(user_info: SendInfo):
    try:
        github_token = os.getenv('GITHUB_TOKEN')  
        repo = "EmmS21/DebtRepayment"
        workflow_id = "run-dagger.yml"
        branch = "main"
 
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }

        data = {
            "ref": "main",
            "inputs": {
                "send_to": user_info.send_to
            }
        }
        response = requests.post(
            f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_id}/dispatches",
            headers=headers,
            json=data
        )
        if response.status_code != 204:
            return {"error": response.text}
        return {"message": "Pipeline triggered, check your email"}
    except Exception as e:
        return {"error": str(e)}


@app.post("/upload_info")
async def upload_user_info(user_info: UserInfo):
    try:
        user = auth.get_user_by_email(user_info.email)
        uid = user.uid

        # Build the custom claims dictionary dynamically
        custom_claims = {
            "apiKey": user_info.apiKey,
            "sheet": user_info.sheet,
            "sheet_two": user_info.sheet_two,
            "name": user_info.name,
            "email_to": user_info.send_to
        }
        custom_claims = {k: v for k, v in custom_claims.items() if v is not None}

        auth.set_custom_user_claims(
            uid,
            custom_claims
        )


        return {"message": "User information uploaded successfully"}
    except auth.UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/sanity_check")
async def sanity_check(user_login: UserLogin):
    try:
        user = auth.get_user_by_email(user_login.email)
        custom_token = auth.create_custom_token(user.uid)
        user_record = auth.get_user(user.uid)  
        custom_claims = user_record.custom_claims

        return {
            "message": "Successfully logged in",
            "uid": user.uid,
            "custom_token": custom_token.decode(),
            "custom_claims": custom_claims
        }
    except auth.UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/test")
def read_root():
    return {"Hello": "World"}
