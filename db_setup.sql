-- Ejecutar como usuario postgres:
--   sudo -u postgres psql -f db_setup.sql

ALTER DATABASE template1 REFRESH COLLATION VERSION;
ALTER DATABASE postgres  REFRESH COLLATION VERSION;

CREATE USER aletheia WITH PASSWORD 'aletheia';
CREATE DATABASE aletheia_db OWNER aletheia ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0;
GRANT ALL PRIVILEGES ON DATABASE aletheia_db TO aletheia;
