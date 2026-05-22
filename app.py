from flask import Flask, request, render_template
import sqlite3

app = Flask(__name__)
DB = 'vuln.db'

# Helper function to get a database connection
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row  # lets us access columns by name
    return conn


# ============================================================
# HOME PAGE — links to all 8 labs
# ============================================================
@app.route('/')
def index():
    return render_template('index.html')


# ============================================================
# LAB 1 — WHERE Clause Hidden Data
# Vulnerability: category input is injected directly into SQL
# Attack payload: ' OR 1=1--
# Effect: bypasses "released=1" filter, shows ALL products
# ============================================================
@app.route('/lab1')
def lab1():
    category = request.args.get('category', '')
    results = []
    query = ''

    if category:
        # VULNERABLE: user input directly concatenated into SQL string
        query = f"SELECT * FROM products WHERE category='{category}' AND released=1"
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(query)   # <-- dangerous! no sanitization
            results = cursor.fetchall()
            conn.close()
        except Exception as e:
            results = []
            query = f"ERROR: {e}"

    return render_template('lab1_products.html',
                           results=results,
                           query=query,
                           category=category)


# ============================================================
# LAB 2 — Login Bypass
# Vulnerability: username field injected into SQL
# Attack payload: administrator'--
# Effect: comments out password check, logs in as admin
# ============================================================
@app.route('/lab2', methods=['GET', 'POST'])
def lab2():
    message = ''
    logged_in_as = ''
    query = ''

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # VULNERABLE: both inputs directly injected into query
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(query)   # <-- dangerous!
            user = cursor.fetchone()
            conn.close()

            if user:
                logged_in_as = user['username']
                message = f"✅ Login successful! Welcome, {logged_in_as}!"
            else:
                message = "❌ Invalid username or password."
        except Exception as e:
            message = f"SQL Error: {e}"

    return render_template('lab2_login.html',
                           message=message,
                           logged_in_as=logged_in_as,
                           query=query)


# ============================================================
# LAB 3 — UNION Attack: Determine Number of Columns
# Vulnerability: search input injected into SQL
# Attack payload: ' UNION SELECT NULL,NULL,NULL--
# Effect: no error = query has 3 columns confirmed
# ============================================================
@app.route('/lab3')
def lab3():
    search = request.args.get('search', '')
    results = []
    query = ''

    if search:
        # VULNERABLE: 3-column query (id, name, description)
        query = f"SELECT id, name, description FROM products WHERE name='{search}'"
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(query)   # <-- dangerous!
            results = cursor.fetchall()
            conn.close()
        except Exception as e:
            results = []
            query = f"ERROR: {e}"

    return render_template('lab3_union.html',
                           results=results,
                           query=query,
                           search=search)


# ============================================================
# LAB 4 — Finding a Text Column
# Vulnerability: same as Lab 3 — injectable search
# Attack payload: ' UNION SELECT 'abc',NULL,NULL--
# Effect: 'abc' appears in col 1 = it's a text column
# Note: id=integer, name=text, description=text
# ============================================================
@app.route('/lab4')
def lab4():
    search = request.args.get('search', '')
    results = []
    query = ''

    if search:
        # VULNERABLE: mix of integer and text columns
        # id (integer), name (text), price (integer shown as text for display)
        query = f"SELECT id, name, category FROM products WHERE name='{search}'"
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(query)   # <-- dangerous!
            results = cursor.fetchall()
            conn.close()
        except Exception as e:
            results = []
            query = f"ERROR: {e}"

    return render_template('lab4_text.html',
                           results=results,
                           query=query,
                           search=search)


# ============================================================
# LAB 5 — Retrieving Data from Other Tables
# Vulnerability: injectable search on products table
# Attack payload: ' UNION SELECT username,password,NULL FROM secret_users--
# Effect: dumps secret_users table credentials
# ============================================================
@app.route('/lab5')
def lab5():
    search = request.args.get('search', '')
    results = []
    query = ''

    if search:
        # VULNERABLE: only meant to search products, but UNION can reach secret_users
        query = f"SELECT id, name, description FROM products WHERE name='{search}'"
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(query)   # <-- dangerous!
            results = cursor.fetchall()
            conn.close()
        except Exception as e:
            results = []
            query = f"ERROR: {e}"

    return render_template('lab5_tables.html',
                           results=results,
                           query=query,
                           search=search)


# ============================================================
# LAB 6 — Multiple Values in a Single Column
# Vulnerability: only ONE usable text column in output
# Attack payload: ' UNION SELECT NULL,username||':'||password,NULL FROM secret_users--
# Effect: combines username and password into one column using SQLite's || operator
# ============================================================
@app.route('/lab6')
def lab6():
    search = request.args.get('search', '')
    results = []
    query = ''

    if search:
        # VULNERABLE: only column 2 (name) is a text column; others are integers
        query = f"SELECT id, name, released FROM products WHERE name='{search}'"
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(query)   # <-- dangerous!
            results = cursor.fetchall()
            conn.close()
        except Exception as e:
            results = []
            query = f"ERROR: {e}"

    return render_template('lab6_multi.html',
                           results=results,
                           query=query,
                           search=search)


# ============================================================
# LAB 7 — Database Version Detection
# Vulnerability: injectable search field
# Attack payload: ' UNION SELECT sqlite_version(),NULL,NULL--
# Effect: returns SQLite version string
# Note: In MySQL you would use @@version instead
# ============================================================
@app.route('/lab7')
def lab7():
    search = request.args.get('search', '')
    results = []
    query = ''

    if search:
        # VULNERABLE: attacker can inject sqlite_version() via UNION
        query = f"SELECT id, name, description FROM products WHERE name='{search}'"
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(query)   # <-- dangerous!
            results = cursor.fetchall()
            conn.close()
        except Exception as e:
            results = []
            query = f"ERROR: {e}"

    return render_template('lab7_version.html',
                           results=results,
                           query=query,
                           search=search)


# ============================================================
# LAB 8 — Listing Database Contents (Schema)
# Vulnerability: injectable search field
# Attack payload 1: ' UNION SELECT name,NULL,NULL FROM sqlite_master WHERE type='table'--
# Attack payload 2: ' UNION SELECT sql,NULL,NULL FROM sqlite_master WHERE name='secret_users'--
# Effect: reveals all table names and their column structure
# Note: In MySQL/PostgreSQL, information_schema.tables is used instead
# ============================================================
@app.route('/lab8')
def lab8():
    search = request.args.get('search', '')
    results = []
    query = ''

    if search:
        # VULNERABLE: sqlite_master is the SQLite equivalent of information_schema
        query = f"SELECT id, name, description FROM products WHERE name='{search}'"
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(query)   # <-- dangerous!
            results = cursor.fetchall()
            conn.close()
        except Exception as e:
            results = []
            query = f"ERROR: {e}"

    return render_template('lab8_schema.html',
                           results=results,
                           query=query,
                           search=search)


# ============================================================
# Run the app
# ============================================================
if __name__ == '__main__':
    print("🚀 Starting Vulnerable Flask SQLi App...")
    print("   Open your browser at: http://localhost:5000")
    print("   Press CTRL+C to stop the server.")
    app.run(debug=True)
