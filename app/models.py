from datetime import datetime, timezone
from app.extensions import db

ROLE_ADMIN   = "admin"
ROLE_ANALYST = "analyst"
ROLE_CLIENT  = "client"


class Organisation(db.Model):
    __tablename__ = "organisations"

    id                  = db.Column(db.Integer,     primary_key=True)
    nombre              = db.Column(db.String(200), nullable=False)
    nif                 = db.Column(db.String(20),  nullable=False, unique=True)
    pais                = db.Column(db.String(100))
    industria           = db.Column(db.String(100))
    fecha_incorporacion = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    email_contacto      = db.Column(db.String(120))
    web                 = db.Column(db.String(200))
    plan                = db.Column(db.String(20),  nullable=False, default="basic")
    is_active           = db.Column(db.SmallInteger, nullable=False, default=1)

    users   = db.relationship("User",   back_populates="organisation", lazy="dynamic")
    scope   = db.relationship("Scope",  back_populates="organisation", lazy="dynamic", cascade="all, delete-orphan")
    reports = db.relationship("Report", back_populates="organisation", lazy="dynamic", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Organisation {self.nombre}>"


class User(db.Model):
    __tablename__ = "users"

    id          = db.Column(db.Integer,     primary_key=True)
    nombre      = db.Column(db.String(100), nullable=False)
    apellido    = db.Column(db.String(100), nullable=False)
    email       = db.Column(db.String(120), nullable=False, unique=True)
    org_id      = db.Column(db.Integer,     db.ForeignKey("organisations.id", ondelete="SET NULL"), nullable=True)
    keycloak_id = db.Column(db.String(36),  nullable=False, unique=True)
    role        = db.Column(db.String(20),  nullable=False, default=ROLE_CLIENT)
    is_active   = db.Column(db.SmallInteger, nullable=False, default=1)
    last_login  = db.Column(db.DateTime,    nullable=True)
    created_at  = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    organisation = db.relationship("Organisation", back_populates="users", foreign_keys=[org_id])
    scope_added  = db.relationship("Scope",  back_populates="added_by_user", lazy="dynamic")
    reports      = db.relationship("Report", back_populates="analyst",       lazy="dynamic")

    @property
    def is_admin(self)   -> bool: return self.role == ROLE_ADMIN
    @property
    def is_analyst(self) -> bool: return self.role == ROLE_ANALYST
    @property
    def is_client(self)  -> bool: return self.role == ROLE_CLIENT
    @property
    def nombre_completo(self) -> str: return f"{self.nombre} {self.apellido}"

    def __repr__(self):
        return f"<User {self.email} ({self.role})>"


class Scope(db.Model):
    __tablename__ = "scope"

    id          = db.Column(db.Integer,     primary_key=True)
    org_id      = db.Column(db.Integer,     db.ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False)
    added_by    = db.Column(db.Integer,     db.ForeignKey("users.id",         ondelete="SET NULL"), nullable=True)
    tipo        = db.Column(db.String(20),  nullable=False)
    valor       = db.Column(db.String(300), nullable=False)
    descripcion = db.Column(db.String(400))
    is_active   = db.Column(db.SmallInteger, nullable=False, default=1)
    added_at    = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    organisation  = db.relationship("Organisation", back_populates="scope",       foreign_keys=[org_id])
    added_by_user = db.relationship("User",         back_populates="scope_added", foreign_keys=[added_by])

    def __repr__(self):
        return f"<Scope {self.tipo}:{self.valor}>"


class Report(db.Model):
    __tablename__ = "reports"

    id             = db.Column(db.Integer,     primary_key=True)
    org_id         = db.Column(db.Integer,     db.ForeignKey("organisations.id", ondelete="CASCADE"),  nullable=False)
    analyst_id     = db.Column(db.Integer,     db.ForeignKey("users.id",         ondelete="SET NULL"), nullable=True)
    titulo         = db.Column(db.String(300), nullable=False)
    descripcion    = db.Column(db.Text)
    scope_snapshot = db.Column(db.JSON)
    resultados     = db.Column(db.JSON)
    output_path    = db.Column(db.String(500))
    is_visible     = db.Column(db.SmallInteger, nullable=False, default=0)
    created_at     = db.Column(db.DateTime,    nullable=False, default=lambda: datetime.now(timezone.utc))

    organisation    = db.relationship("Organisation", back_populates="reports",         foreign_keys=[org_id])
    analyst         = db.relationship("User",         back_populates="reports",         foreign_keys=[analyst_id])
    tool_executions = db.relationship("ToolExecution", back_populates="report",         lazy="dynamic", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Report #{self.id} '{self.titulo}'>"


class PipelineAnalysis(db.Model):
    __tablename__ = "pipeline_analyses"

    id         = db.Column(db.Integer,  primary_key=True)
    user_id    = db.Column(db.Integer,  db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    seeds      = db.Column(db.JSON,     nullable=False)
    assets     = db.Column(db.JSON,     nullable=False, default=list)
    score      = db.Column(db.Integer,  nullable=False, default=0)
    findings   = db.Column(db.JSON,     nullable=False, default=list)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    user = db.relationship("User", foreign_keys=[user_id])

    def __repr__(self):
        return f"<PipelineAnalysis #{self.id} score={self.score}>"


class ManualAnalysis(db.Model):
    __tablename__ = "manual_analyses"

    id         = db.Column(db.Integer,  primary_key=True)
    user_id    = db.Column(db.Integer,  db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    targets    = db.Column(db.JSON,     nullable=False)
    tools      = db.Column(db.JSON,     nullable=False, default=list)
    findings   = db.Column(db.JSON,     nullable=False, default=list)
    score      = db.Column(db.Integer,  nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    user = db.relationship("User", foreign_keys=[user_id])

    def __repr__(self):
        return f"<ManualAnalysis #{self.id} score={self.score}>"


class ToolExecution(db.Model):
    __tablename__ = "tool_executions"

    id            = db.Column(db.Integer,     primary_key=True)
    report_id     = db.Column(db.Integer,     db.ForeignKey("reports.id", ondelete="CASCADE"), nullable=False)
    tool_name     = db.Column(db.String(100), nullable=False)
    comando       = db.Column(db.Text,        nullable=False)
    status        = db.Column(db.String(20),  nullable=False, default="running")
    exit_code     = db.Column(db.Integer)
    error_message = db.Column(db.Text)
    started_at    = db.Column(db.DateTime,    nullable=False, default=lambda: datetime.now(timezone.utc))
    finished_at   = db.Column(db.DateTime)
    duration_secs = db.Column(db.Integer)

    report = db.relationship("Report", back_populates="tool_executions")

    def __repr__(self):
        return f"<ToolExecution {self.tool_name} [{self.status}]>"
