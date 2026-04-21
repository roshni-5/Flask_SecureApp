from app import app, db, User, bcrypt

with app.app_context():
    # Check if admin exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        hashed = bcrypt.generate_password_hash('admin123').decode('utf-8')
        admin_user = User(username='admin', password_hash=hashed, is_admin=True)
        db.session.add(admin_user)
        db.session.commit()
        print("✓ Admin user created!")
        print("  Username: admin")
        print("  Password: admin123")
    else:
        print("Admin user already exists")
    
    # List all users
    print("\nAll users:")
    users = User.query.all()
    for user in users:
        print(f"  - {user.username} (Admin: {user.is_admin})")