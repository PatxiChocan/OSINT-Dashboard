-- Aletheia Database Schema — PostgreSQL
-- Ejecutar: sudo -u postgres psql -f aletheia.sql

-- -----------------------------------------------------
-- Base de datos y usuario
-- -----------------------------------------------------
CREATE USER aletheia WITH PASSWORD 'aletheia';
CREATE DATABASE aletheia_db OWNER aletheia ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0;
GRANT ALL PRIVILEGES ON DATABASE aletheia_db TO aletheia;

\c aletheia_db

-- Schema para Keycloak separado
CREATE SCHEMA keycloak;
GRANT ALL ON SCHEMA keycloak TO aletheia;

-- -----------------------------------------------------
-- Tipos ENUM
-- -----------------------------------------------------
CREATE TYPE plan_tipo   AS ENUM ('basic', 'pro', 'enterprise');
CREATE TYPE user_role   AS ENUM ('admin', 'analyst', 'client');
CREATE TYPE scope_tipo  AS ENUM ('domain', 'subdomain', 'ip', 'cidr', 'email', 'username');
CREATE TYPE tool_status AS ENUM ('running', 'success', 'error', 'timeout');

-- -----------------------------------------------------
-- Table: organisations
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS organisations (
    id                  SERIAL          PRIMARY KEY,
    nombre              VARCHAR(200)    NOT NULL,
    nif                 VARCHAR(20)     NOT NULL UNIQUE,
    pais                VARCHAR(100),
    industria           VARCHAR(100),
    fecha_incorporacion TIMESTAMP       DEFAULT CURRENT_TIMESTAMP,
    email_contacto      VARCHAR(120),
    web                 VARCHAR(200),
    plan                plan_tipo       NOT NULL DEFAULT 'basic',
    is_active           SMALLINT        NOT NULL DEFAULT 1
);

-- -----------------------------------------------------
-- Table: users
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id          SERIAL          PRIMARY KEY,
    nombre      VARCHAR(100)    NOT NULL,
    apellido    VARCHAR(100)    NOT NULL,
    email       VARCHAR(120)    NOT NULL UNIQUE,
    org_id      INT             REFERENCES organisations(id) ON DELETE SET NULL ON UPDATE CASCADE,
    keycloak_id VARCHAR(36)     NOT NULL UNIQUE,
    role        user_role       NOT NULL DEFAULT 'client',
    is_active   SMALLINT        NOT NULL DEFAULT 1,
    last_login  TIMESTAMP,
    created_at  TIMESTAMP       DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------
-- Table: scope
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS scope (
    id          SERIAL          PRIMARY KEY,
    org_id      INT             NOT NULL REFERENCES organisations(id) ON DELETE CASCADE ON UPDATE CASCADE,
    added_by    INT             REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE,
    tipo        scope_tipo      NOT NULL,
    valor       VARCHAR(300)    NOT NULL,
    descripcion VARCHAR(400),
    is_active   SMALLINT        NOT NULL DEFAULT 1,
    added_at    TIMESTAMP       DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------
-- Table: reports
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    id              SERIAL          PRIMARY KEY,
    org_id          INT             NOT NULL REFERENCES organisations(id) ON DELETE CASCADE ON UPDATE CASCADE,
    analyst_id      INT             REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE,
    titulo          VARCHAR(300)    NOT NULL,
    descripcion     TEXT,
    scope_snapshot  JSONB,
    resultados      JSONB,
    output_path     VARCHAR(500),
    is_visible      SMALLINT        NOT NULL DEFAULT 0,
    created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------
-- Table: tool_executions
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS tool_executions (
    id            SERIAL          PRIMARY KEY,
    report_id     INT             NOT NULL REFERENCES reports(id) ON DELETE CASCADE ON UPDATE CASCADE,
    tool_name     VARCHAR(100)    NOT NULL,
    comando       TEXT            NOT NULL,
    status        tool_status     NOT NULL DEFAULT 'running',
    exit_code     INT,
    error_message TEXT,
    started_at    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at   TIMESTAMP,
    duration_secs INT
);

-- -----------------------------------------------------
-- Índices
-- -----------------------------------------------------
CREATE INDEX idx_users_org       ON users(org_id);
CREATE INDEX idx_scope_org       ON scope(org_id);
CREATE INDEX idx_scope_added_by  ON scope(added_by);
CREATE INDEX idx_reports_org     ON reports(org_id);
CREATE INDEX idx_reports_analyst ON reports(analyst_id);
CREATE INDEX idx_toolexec_report ON tool_executions(report_id);
