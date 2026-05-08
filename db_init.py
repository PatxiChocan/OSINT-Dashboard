"""
Crea todas las tablas y el usuario administrador inicial.
Ejecutar una sola vez: venv/bin/python db_init.py
"""
from app import create_app
from app.extensions import db
from app.models import User, ROLE_ADMIN

app = create_app()

with app.app_context():
    db.create_all()
    print("Tablas creadas.")

    if not User.query.filter_by(username="admin").first():
        admin = User(
            username="admin",
            email="admin@aletheia.local",
            role=ROLE_ADMIN,
        )
        admin.set_password("admin1234")
        db.session.add(admin)
        db.session.commit()
        print("Usuario admin creado  →  admin / admin1234")
    else:
        print("Usuario admin ya existe.")
