from app import app, db, User
from werkzeug.security import generate_password_hash
import os
import getpass # Use this to hide the password while typing

with app.app_context():
    try:
        print("[*] Creating database tables...")
        db.create_all()

        # 1. Get User Input
        print("\n--- [ NEW USER SETUP ] ---")
        new_username = input("Enter username: ").strip()
        
        # getpass hides the password characters as you type for better OPSEC
        new_password = getpass.getpass("Enter password: ")
        
        if not new_username or not new_password:
            print("❌ ERROR: Username and Password cannot be empty.")
        else:
            # 2. Check if user already exists
            if not User.query.filter_by(username=new_username).first():
                print(f"[*] Creating user: {new_username}...")
                
                new_user = User(
                    username=new_username, 
                    password=generate_password_hash(new_password)
                )
                
                db.session.add(new_user)
                db.session.commit()
                print(f"✅ User '{new_username}' created successfully.")
            else:
                print(f"[!] User '{new_username}' already exists in the database.")

        print(f"\n✅ Database initialized at: {os.path.join(os.getcwd(), 'draxer.db')}")

    except Exception as e:
        print(f"❌ ERROR: {e}")
