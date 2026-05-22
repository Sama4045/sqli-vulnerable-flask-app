import sqlite3

# This file creates the SQLite database and fills it with sample data.
# Run this ONCE before starting the Flask app: python database.py

def init_db():
    # Connect to (or create) the database file
    conn = sqlite3.connect('vuln.db')
    cursor = conn.cursor()

    # -------------------------------------------------------
    # TABLE 1: products
    # Used in Labs 1, 3, 4, 5, 6, 7, 8
    # 'released' column: 1 = visible to public, 0 = hidden
    # -------------------------------------------------------
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            description TEXT,
            category    TEXT,
            released    INTEGER DEFAULT 1
        )
    ''')

    # -------------------------------------------------------
    # TABLE 2: users
    # Used in Lab 2 (login bypass)
    # -------------------------------------------------------
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # -------------------------------------------------------
    # TABLE 3: secret_users
    # Used in Labs 5 and 6 (cross-table UNION attacks)
    # This table is NOT linked from the UI — only reachable via SQLi
    # -------------------------------------------------------
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secret_users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # -------------------------------------------------------
    # SEED DATA — only insert if tables are empty
    # -------------------------------------------------------

    # Products: mix of released (1) and hidden/unreleased (0)
    cursor.execute("SELECT COUNT(*) FROM products")
    if cursor.fetchone()[0] == 0:
        products = [
            ('Laptop Pro',      'High-performance laptop',     'Electronics', 1),
            ('USB-C Hub',       '7-in-1 USB hub',              'Electronics', 1),
            ('Wireless Mouse',  'Ergonomic wireless mouse',    'Electronics', 1),
            ('Secret Phone X',  'Unreleased flagship phone',   'Electronics', 0),  # HIDDEN
            ('Budget Tablet',   'Affordable 8-inch tablet',    'Electronics', 0),  # HIDDEN
            ('Python Book',     'Learn Python in 30 days',     'Books',       1),
            ('Hacking Guide',   'Ethical hacking handbook',    'Books',       1),
            ('Top Secret Doc',  'Classified product manual',   'Books',       0),  # HIDDEN
            ('Office Chair',    'Lumbar support chair',        'Furniture',   1),
            ('Standing Desk',   'Adjustable height desk',      'Furniture',   1),
        ]
        cursor.executemany(
            "INSERT INTO products (name, description, category, released) VALUES (?, ?, ?, ?)",
            products
        )

    # Normal users (used for Lab 2 login bypass)
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        users = [
            ('administrator', 'supersecret123'),
            ('alice',         'alice_pass'),
            ('bob',           'bob_pass'),
        ]
        cursor.executemany(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            users
        )

    # Secret users (only reachable via UNION injection in Labs 5 & 6)
    cursor.execute("SELECT COUNT(*) FROM secret_users")
    if cursor.fetchone()[0] == 0:
        secret_users = [
            ('admin',    'password123'),
            ('root',     'toor'),
            ('wiener',   'peter'),
            ('carlos',   'montoya'),
        ]
        cursor.executemany(
            "INSERT INTO secret_users (username, password) VALUES (?, ?)",
            secret_users
        )

    conn.commit()
    conn.close()
    print("✅ Database created successfully: vuln.db")
    print("   Tables: products, users, secret_users")
    print("   Sample data inserted.")
    print("   Now run: python app.py")


if __name__ == '__main__':
    init_db()
