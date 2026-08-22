import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.db.session import SessionLocal
from app.db.tenancy import bypass_tenant, clear_tenant
from app.core.security import hash_password
from sqlalchemy import text

def update_password():
    db = SessionLocal()
    try:
        bypass_tenant(db)
        new_hash = hash_password("Ram15890$$")
        result = db.execute(
            text("UPDATE users SET hashed_password = :hash WHERE email = :email"),
            {"hash": new_hash, "email": "ykamranali7777@gmail.com"}
        )
        db.commit()
        print(f"Password updated successfully using raw SQL. Rows affected: {result.rowcount}")
    finally:
        clear_tenant(db)
        db.commit()
        db.close()

if __name__ == "__main__":
    update_password()
