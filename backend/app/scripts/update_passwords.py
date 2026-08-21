from app.db.session import SessionLocal
from app.models.user import User
from app.core.security import hash_password

def update_passwords():
    db = SessionLocal()
    from app.db.tenancy import bypass_tenant
    bypass_tenant(db)
    new_password = hash_password('Ram15890$$')
    users = db.query(User).all()
    for u in users:
        u.hashed_password = new_password
    db.commit()
    db.close()
    print(f"Updated passwords for {len(users)} users to Ram15890$$")

if __name__ == "__main__":
    update_passwords()
