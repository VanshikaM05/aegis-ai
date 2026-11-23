from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
import joblib
import pandas as pd
import json
import hashlib
import secrets
import time
import psycopg2
import os
from fastapi import UploadFile, File
from io import BytesIO


app = FastAPI()

# POSTGRESQL DATABASE CONNECTION

DB_CONFIG = {
    "host": "localhost",
    "database": "aegis_db",
    "user": "aegis_app",
    "password": os.environ.get("AEGIS_DB_PASSWORD")
}

def get_db_connection():
    if not DB_CONFIG["password"]:
        raise RuntimeError("AEGIS_DB_PASSWORD environment variable is not set.")

    return psycopg2.connect(**DB_CONFIG)

# AEGIS AI AUTHENTICATION WITH POSTGRESQL

# Temporary login tokens (30-minute expiry)
active_tokens = {}

security = HTTPBearer()


# VERIFY AUTHENTICATION TOKEN

def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    session = active_tokens.get(token)

    if not session:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token."
        )

    if time.time() > session["expires"]:
        active_tokens.pop(token, None)

        raise HTTPException(
            status_code=401,
            detail="Authentication token expired. Please login again."
        )

    return session["username"]


# REGISTER NEW USER

@app.post("/register")
def register(data: dict):

    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    if not username or not password:
        return {"error": "Username and password are required"}

    if len(username) < 3 or len(username) > 50:
        return {"error": "Username must be between 3 and 50 characters"}

    if len(password) < 8:
        return {"error": "Password must contain at least 8 characters"}

    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200000
    ).hex()

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO users (username, salt, password_hash)
            VALUES (%s, %s, %s)
            """,
            (username, salt.hex(), password_hash)
        )

        conn.commit()

        cursor.close()
        conn.close()

        return {"message": "Account created successfully"}

    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        cursor.close()
        conn.close()

        return {"error": "Username already exists"}

    except Exception:
        if "conn" in locals():
            conn.rollback()
            conn.close()

        raise HTTPException(
            status_code=500,
            detail="Registration failed. Please try again."
        )


# USER LOGIN

@app.post("/login")
def login(data: dict):

    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT salt, password_hash FROM users WHERE username = %s",
        (username,)
    )

    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        return {"error": "Invalid username or password"}

    salt = bytes.fromhex(user[0])

    entered_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200000
    ).hex()

    if not secrets.compare_digest(entered_hash, user[1]):
        return {"error": "Invalid username or password"}

    token = secrets.token_urlsafe(32)

    active_tokens[token] = {
        "username": username,
        "expires": time.time() + 1800
    }

    return {
        "message": "Login successful",
        "username": username,
        "access_token": token,
        "token_type": "bearer"
    }

# SERVER-SIDE LOGOUT

@app.post("/logout")
def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    user: str = Depends(verify_token)
):
    token = credentials.credentials

    active_tokens.pop(token, None)

    return {
        "message": "Logout successful. Token revoked."
    }

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

model = joblib.load("../angis_final_model.pkl")


with open("features.json", "r") as f:
    feature_names = json.load(f)


def build_early_warning(results):
    total = len(results)

    if total == 0:
        return {
            "level": "NORMAL",
            "suspicious_count": 0,
            "suspicious_rate": 0.0,
            "message": "No traffic records analyzed."
        }

    suspicious = [
        item for item in results
        if item["threat"] != "BENIGN"
    ]

    count = len(suspicious)
    rate = (count / total) * 100

    if rate >= 10:
        level = "CRITICAL"
        message = "High proportion of suspicious traffic detected."
    elif rate > 0:
        level = "ELEVATED"
        message = "Suspicious traffic detected. Further investigation recommended."
    else:
        level = "NORMAL"
        message = "No suspicious traffic detected in this batch."

    return {
        "level": level,
        "records_analyzed": total,
        "suspicious_count": count,
        "suspicious_rate": round(rate, 2),
        "message": message
    }

@app.get("/")
def home():
    return {
         "message": "ANGIS AI backend is running!",
         "model": "Random Forest",
         "classes": model.classes_.tolist(),
         "features": len(feature_names)

       }

@app.post("/predict")
def predict(
    data: dict,
    user: str = Depends(verify_token)
    ):
    missing = [feature for feature in feature_names if feature not in data]

    if missing:
        return {
            "error": "Missing features",
            "missing_count": len(missing)
        }
    
    try:
        values = [[
            float(data[feature])
            for feature in feature_names
        ]]
    except (TypeError, ValueError):
        return {
            "error": "Invalid input",
            "message": "All feature values must be numeric."
        }

    if not all(
        pd.notna(value) and abs(value) != float("inf")
        for value in values[0]
    ):
        return {
            "error": "Invalid input",
            "message": "Feature values cannot be empty or infinite."
        }

    x = pd.DataFrame(values, columns=feature_names)

    prediction = model.predict(x)[0]

    if prediction == "BENIGN":
       severity = "LOW"
       warning = "No threat detected"

    elif prediction == "Bot":
         severity = "HIGH"
         warning = "Potential Bot attack detected"

    elif prediction == "FTP-Patator":
         severity = "HIGH"
         warning = "FTP brute-force attack detected"

    elif prediction == "SSH-Patator":
         severity = "HIGH"
         warning = "SSH brute-force attack detected"

    else:
        severity = "UNKNOWN"
        warning = "Unknown threat detected"

    return {
       "threat": prediction,
       "severity": severity,
       "warning": warning
  }

@app.post("/predict-csv")
async def predict_csv(
    file: UploadFile = File(...),
    user: str = Depends(verify_token)
    ):
    # Limit uploaded files to 5 MB
    max_size = 5 * 1024 * 1024
    content = await file.read(max_size + 1)

    if len(content) > max_size:
        return {
            "error": "File too large",
            "message": "CSV files must be 5 MB or smaller."
        }

    if not content:
        return {
            "error": "Empty file",
            "message": "Please upload a non-empty CSV file."
        }

    try:
        # Read only the column headers first
        headers = pd.read_csv(BytesIO(content), nrows=0).columns.tolist()

        missing = [name for name in feature_names if name not in headers]

        if missing:
            return {
                "error": "Missing features",
                "missing_count": len(missing),
                "missing_features": missing
            }

        results = []
        total_rows = 0
        batch_size = 250
        max_rows = 5000

        # Process the CSV in small batches
        for chunk in pd.read_csv(BytesIO(content), chunksize=batch_size):
            if len(chunk) == 0:
                continue

            total_rows += len(chunk)

            if total_rows > max_rows:
                return {
                    "error": "Too many rows",
                    "message": "CSV files may contain at most 5000 data rows."
                }

            # Use the exact feature order expected by the model
            chunk = chunk[feature_names]

            # Convert every feature to a numeric value
            numeric = chunk.apply(pd.to_numeric, errors="coerce")

            # Reject missing, invalid, NaN, and infinite values
            invalid = (
                numeric.isna()
            |   numeric.eq(float("inf"))
            |   numeric.eq(float("-inf"))
        )

            if invalid.any().any():
                bad_rows = invalid.any(axis=1)
                row_numbers = [
                    int(index) + 2
                    for index in chunk.index[bad_rows][:10]
                ]

                return {
                    "error": "Invalid input",
                    "message": (
                        "CSV values must be numeric, non-empty, "
                        "and finite."
                    ),
                    "invalid_csv_rows": row_numbers
                }

            predictions = model.predict(numeric)

            for prediction in predictions:
                if prediction == "BENIGN":
                    severity = "LOW"
                    warning = "No threat detected"
                elif prediction == "Bot":
                    severity = "HIGH"
                    warning = "Potential Bot attack detected"
                elif prediction == "FTP-Patator":
                    severity = "HIGH"
                    warning = "FTP brute-force attack detected"
                elif prediction == "SSH-Patator":
                    severity = "HIGH"
                    warning = "SSH brute-force attack detected"
                else:
                    severity = "UNKNOWN"
                    warning = "Unknown threat detected"

                results.append({
                    "threat": str(prediction),
                    "severity": severity,
                    "warning": warning
                })

        if total_rows == 0:
            return {
                "error": "No data rows",
                "message": "The CSV contains headers but no data rows."
            }

        return {
                "total_rows": total_rows,
                "results": results,
                "early_warning": build_early_warning(results)
            }

    except (ValueError, UnicodeDecodeError, pd.errors.ParserError):
        return {
           "error": "Invalid CSV",
            "message": (
                "Unable to read the file. Please upload a valid "
                "UTF-8 CSV file."
            )
        }
    except Exception:
        return {
            "error": "Analysis failed",
            "message": "The CSV could not be analyzed."
        }
    finally:
        await file.close()
