import os

import psycopg2

if __name__ == '__main__':
    # Replace with your actual DATABASE_URL or use an environment variable
    try:
        DATABASE_URL = os.getenv("DATABASE_URL")

        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()

        # Get all user-defined tables
        cur.execute("""
                    SELECT table_name
                    FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
                    """)

        tables = cur.fetchall()

        for table in tables:
            table_name = table[0]
            print(f"\n-- DDL for table: {table_name}")

            # Get column info
            cur.execute("""
                        SELECT column_name, data_type, is_nullable, column_default
                        FROM information_schema.columns
                        WHERE table_name = %s;
                        """, (table_name,))

            columns = cur.fetchall()

            ddl = f"CREATE TABLE {table_name} (\n"
            col_lines = []
            for col in columns:
                line = f"  {col[0]} {col[1]}"
                if col[3]:
                    line += f" DEFAULT {col[3]}"
                if col[2] == "NO":
                    line += " NOT NULL"
                col_lines.append(line)
            ddl += ",\n".join(col_lines) + "\n);"
            print(ddl)

        cur.close()
        conn.close()
    except Exception as e:
        print(f"An error occurred: {e}")
        exit(1)
