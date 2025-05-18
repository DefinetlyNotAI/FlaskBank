import os

from psycopg2.pool import ThreadedConnectionPool

DATABASE_URL = os.environ.get("DATABASE_URL", "EMPTY")
if DATABASE_URL == "EMPTY":
    print("The Database URL env variable is missing, THIS IS A MAJOR ISSUE!!")
MAX_CONNECTION_POOL = 20  # Set the maximum number of connections in the pool for PostgreSQL

# Database connection pool
DB_POOL = None
if DATABASE_URL != "EMPTY":
    try:
        DB_POOL = ThreadedConnectionPool(1, MAX_CONNECTION_POOL, DATABASE_URL)
        print("\033[92mDatabase connection pool initialized successfully\033[0m")
    except Exception as err:
        print("\033[91mError initializing database connection pool:\033[0m", err)
        DB_POOL = None
else:
    print("Database connection pool skipped successfully, the default pages will show ONLY")
