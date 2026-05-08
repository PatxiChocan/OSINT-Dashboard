from datetime import datetime, timezone
from flask_login import UserMixin
from app.extensions import db, bcrypt

# ── Roles ─────────────────────────────────────────────────────────────────────
ROLE_ADMIN   = "admin"
ROLE_ANALYST = "analyst"
ROLE_CLIENT  = "client"
VALID_ROLES  = (ROLE_ADMIN, ROLE_ANALYST, ROLE_CLIENT)


# ── Association: analistas ↔ clientes ────────────────────────────────────────
analyst_clients = db.Table(
    "analyst_clients",
    db.Column("analyst_id", db.Integer, db.ForeignKey("users.id",   ondelete="CASCADE"), primary_key=True),
    db.Column("client_id",  db.Integer, db.ForeignKey("clients.id", ondelete="CASCADE"), primary_key=True),
    db.Column("assigned_at", db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)),
)

# ── Association: usuarios cliente ↔ clientes ─────────────────────────────────
client_user_access = db.Table(
    "client_user_access",
    db.Column("user_id",   db.Integer, db.ForeignKey("users.id",   ondelete="CASCADE"), primary_key=True),
    db.Column("client_id", db.Integer, db.ForeignKey("clients.id", ondelete="CASCADE"), primary_key=True),
)


# ── User ──────────────────────────────────────────────────────────────────────
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role          = db.Column(db.String(20),  nullable=False, default=ROLE_ANALYST)
    is_active     = db.Column(db.Boolean,     nullable=False, default=True)
    created_at    = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_login    = db.Column(db.DateTime(timezone=True), nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # Relationships
    created_by = db.relationship("User", remote_side=[id], backref="created_users", foreign_keys=[created_by_id])

    # Analysts ↔ clients (for analyst role)
    assigned_clients = db.relationship(
        "Client", secondary=analyst_clients, back_populates="analysts",
        lazy="dynamic"
    )
    # Client users ↔ clients (for client role)
    accessible_clients = db.relationship(
        "Client", secondary=client_user_access, back_populates="client_users",
        lazy="dynamic"
    )

    def set_password(self, password: str):
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, password)

    @property
    def is_admin(self)    -> bool: return self.role == ROLE_ADMIN
    @property
    def is_analyst(self)  -> bool: return self.role == ROLE_ANALYST
    @property
    def is_client_role(self) -> bool: return self.role == ROLE_CLIENT

    def can_access_client(self, client_id: int) -> bool:
        if self.is_admin:
            return True
        if self.is_analyst:
            return self.assigned_clients.filter_by(id=client_id).first() is not None
        if self.is_client_role:
            return self.accessible_clients.filter_by(id=client_id).first() is not None
        return False

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


# ── Client (organización objetivo) ────────────────────────────────────────────
class Client(db.Model):
    __tablename__ = "clients"

    id             = db.Column(db.Integer, primary_key=True)
    name           = db.Column(db.String(200), nullable=False)
    description    = db.Column(db.Text,   nullable=True)
    scope_domains  = db.Column(db.Text,   nullable=True)  # CSV de dominios
    scope_ips      = db.Column(db.Text,   nullable=True)  # CSV de rangos IP
    is_active      = db.Column(db.Boolean, nullable=False, default=True)
    created_at     = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    created_by_id  = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # Relationships
    created_by   = db.relationship("User", foreign_keys=[created_by_id])
    analysts     = db.relationship("User", secondary=analyst_clients,   back_populates="assigned_clients")
    client_users = db.relationship("User", secondary=client_user_access, back_populates="accessible_clients")
    reports      = db.relationship("Report", back_populates="client", lazy="dynamic", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Client {self.name}>"


# ── Report (sesión de análisis guardada) ──────────────────────────────────────
class Report(db.Model):
    __tablename__ = "reports"

    id          = db.Column(db.Integer, primary_key=True)
    client_id   = db.Column(db.Integer, db.ForeignKey("clients.id", ondelete="CASCADE"), nullable=False)
    analyst_id  = db.Column(db.Integer, db.ForeignKey("users.id",   ondelete="SET NULL"), nullable=True)
    title       = db.Column(db.String(300), nullable=False)
    scope       = db.Column(db.JSON,  nullable=True)   # snapshot del scope
    summary     = db.Column(db.JSON,  nullable=True)   # resumen estructurado
    raw_output  = db.Column(db.Text,  nullable=True)   # output completo de consola
    is_visible  = db.Column(db.Boolean, nullable=False, default=False)  # visible al rol cliente
    created_at  = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    client  = db.relationship("Client", back_populates="reports")
    analyst = db.relationship("User", foreign_keys=[analyst_id])
    tool_executions = db.relationship("ToolExecution", back_populates="report", lazy="dynamic", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Report #{self.id} '{self.title}'>"


# ── ToolExecution (log de cada herramienta ejecutada) ─────────────────────────
class ToolExecution(db.Model):
    __tablename__ = "tool_executions"

    id           = db.Column(db.Integer, primary_key=True)
    report_id    = db.Column(db.Integer, db.ForeignKey("reports.id",  ondelete="SET NULL"), nullable=True)
    analyst_id   = db.Column(db.Integer, db.ForeignKey("users.id",    ondelete="SET NULL"), nullable=True)
    client_id    = db.Column(db.Integer, db.ForeignKey("clients.id",  ondelete="SET NULL"), nullable=True)
    tool_name    = db.Column(db.String(100), nullable=False)
    command      = db.Column(db.Text,        nullable=False)
    status       = db.Column(db.String(20),  nullable=False, default="running")
    # status: running | success | error | timeout
    exit_code      = db.Column(db.Integer, nullable=True)
    error_message  = db.Column(db.Text,    nullable=True)
    started_at     = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    finished_at    = db.Column(db.DateTime(timezone=True), nullable=True)
    duration_secs  = db.Column(db.Integer, nullable=True)

    # Relationships
    report  = db.relationship("Report", back_populates="tool_executions")
    analyst = db.relationship("User",   foreign_keys=[analyst_id])
    client  = db.relationship("Client", foreign_keys=[client_id])

    def __repr__(self):
        return f"<ToolExecution {self.tool_name} [{self.status}]>"
