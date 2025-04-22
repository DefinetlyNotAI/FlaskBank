import os

import psycopg2
from psycopg2.extras import RealDictCursor

# Database connection string
DB_URL = os.environ.get("DATABASE_URL")


def get_tables(db_url):
    try:
        conn = psycopg2.connect(db_url)
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
                       SELECT table_name
                       FROM information_schema.tables
                       WHERE table_schema = 'public'
                       """)
        tables = [row['table_name'] for row in cursor.fetchall()]
        cursor.close()
        conn.close()
        return tables
    except Exception as e:
        print(f"Error: {e}")
        return None


def get_table_content(db_url, table_name):
    try:
        conn = psycopg2.connect(db_url)
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"SELECT * FROM {table_name} LIMIT 10;")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    except Exception as e:
        print(f"Error: {e}")
        return None


def delete_table(db_url, table_name):
    try:
        conn = psycopg2.connect(db_url)
        cursor = conn.cursor()
        cursor.execute(f"DROP TABLE IF EXISTS {table_name} CASCADE;")
        conn.commit()
        cursor.close()
        conn.close()
        print(f"Table '{table_name}' deleted successfully.")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    while True:
        print("\nMenu:")
        print("1. List tables")
        print("2. Check table content")
        print("3. Delete a table")
        print("4. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            tables = get_tables(DB_URL)
            if tables:
                print("Tables:")
                for table in tables:
                    print(f"- {table}")
            else:
                print("No tables found or an error occurred.")

        elif choice == '2':
            table_name = input("Enter the table name to check content: ").strip()
            rows = get_table_content(DB_URL, table_name)
            if rows:
                print(f"Content of table '{table_name}':")
                for row in rows:
                    print(row)
            else:
                print(f"No content found or an error occurred for table '{table_name}'.")

        elif choice == '3':
            table_name = input("Enter the table name to delete: ").strip()
            confirm = input(f"Are you sure you want to delete the table '{table_name}'? (yes/no): ").strip().lower()
            if confirm == 'yes':
                delete_table(DB_URL, table_name)
            else:
                print("Deletion canceled.")

        elif choice == '4':
            print("Exiting program.")
            break

        else:
            print("Invalid choice. Please try again.")
