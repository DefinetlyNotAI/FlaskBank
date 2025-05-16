import os

from psycopg2.pool import ThreadedConnectionPool

DATABASE_URL = os.environ.get("DATABASE_URL", "EMPTY")
if DATABASE_URL == "EMPTY":
    print("The Database URL env variable is missing, THIS IS A MAJOR ISSUE!!")
MAX_CONNECTION_POOL = 20  # Set the maximum number of connections in the pool for PostgreSQL

"""
We advise to keep this FALSE as it may undermine security and 
put too much pressure on servers if set to True, admins bypass this automatically

If TRUE, it will only allow access to the endpoint if:
    1. User is an admin
    2. Request is from the same origin (the website)
    3. It's a GET request for public endpoints (logs, leaderboard, currency pool)
Else, it will allow any API request from any origin (DDoS risk)
"""
ALLOW_PUBLIC_API_ACCESS = False

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
