from flask import Flask
from flask import request
from flask import redirect
from flask import render_template
from flask import session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity,
    get_jwt
)

import sqlite3
import re

from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)

app = Flask(__name__)
app.secret_key="student123"
app.config["JWT_SECRET_KEY"] = "jwtstudent123"
jwt = JWTManager(app)

# Func that helps accessing rows by col_name from table
def get_db_connection():
    conn = sqlite3.connect("students.db")
    conn.row_factory = sqlite3.Row
    return conn

# Database creation
def db():
    conn = sqlite3.connect("students.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS students(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT,
    last_name TEXT,
    email TEXT,
    phone_number TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP DEFAULT NULL
    )""")
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    phone_number TEXT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP DEFAULT NULL
    )""")
    
    conn.commit()
    conn.close()
db()

# api login authentication
@app.route("/api/login", methods=["POST"])
def api_login():
    email=request.json.get("email")
    password=request.json.get("password")

    conn=get_db_connection()
    cursor=conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=? AND deleted_at IS NULL",(email,))
    user=cursor.fetchone()
    conn.close()

    if user is None:
        return {
            "message":"Invalid Email"
        },401
    if not check_password_hash(
        user["password"],
        password
    ):
        return {
            "message":"Invalid Password"
        },401

    token=create_access_token(
        identity=user["email"],
        additional_claims={
            "username": user["username"],
            "role": user["role"]
        }
    )

    return {
        "access_token":token
    },200

# api home
@app.route("/api/home")
@jwt_required()
def api_home():

    current_user=get_jwt_identity()
    return {
        "message":"Welcome",
        "user":current_user
    }

# students api
@app.route("/api/students")
@jwt_required()
def api_students():
    # Information from JWT token
    email = get_jwt_identity()
    claims = get_jwt()
    role = claims["role"]
    
    conn=get_db_connection()
    cursor=conn.cursor()
    cursor.execute("SELECT * FROM students WHERE deleted_at IS NULL")
    students=cursor.fetchall()
    conn.close()
    data=[]
    for student in students:
        data.append({
            "id":student["id"],
            "first_name":student["first_name"],
            "last_name":student["last_name"],
            "email":student["email"]
        })
    return {
        "logged_in_user": email,
        "role": role,
        "students": data
    }

# delete api
@app.route("/api/delete/<int:id>")
@jwt_required()
def api_delete(id):
    claims = get_jwt()
    if claims["role"]!="admin":
        return {
            "message":"Access Denied"
        },403
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""UPDATE students SET deleted_at = CURRENT_TIMESTAMP,
                   updated_at=CURRENT_TIMESTAMP WHERE id=?""",(id,))
    conn.commit()
    conn.close()
    return {
        "message": "Student Deleted Successfully"
    }  

# Sign up
@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method=="POST":
        username=request.form["username"]
        email=request.form["email"]
        password=request.form["password"]
        phone_number = request.form["phone_number"]
        role = request.form["role"]
        
        if not re.fullmatch(r"\d{10}", phone_number):
            return render_template("signup.html",
        error="Phone number must contain exactly 10 digits.")
    
        hashed_password=generate_password_hash(password)

        conn=get_db_connection()
        cursor=conn.cursor()
        # Check email exists
        cursor.execute(
            "SELECT * FROM users WHERE email=? AND deleted_at IS NULL",
            (email,)
        )
        existing_user=cursor.fetchone()

        if existing_user:
            conn.close()
            return render_template(
                "signup.html",
                error="Email already exists. Please use another email.")
            
        
        cursor.execute("""
        INSERT INTO users(username,email,password,phone_number,role)
        VALUES(?,?,?,?,?)""",(username,email,hashed_password,phone_number,role))
        
        conn.commit()
        conn.close()
        return redirect("/")
    return render_template("signup.html")
    
# login 
@app.route("/",methods=["GET","POST"])
def login():
    if request.method=="POST":
        email=request.form["email"]
        password=request.form["password"]

        conn=get_db_connection()
        cursor=conn.cursor()
        
        cursor.execute(
        "SELECT * FROM users WHERE email=?",
        (email,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user["password"],password):
            session["user"] = user["username"]
            session["role"] = user["role"].strip().lower()
            session["email"]=user["email"]
            return redirect("/home")
        else:
            return "Invalid email or password"
    return render_template("login.html")

# Home page
@app.route("/home")
def home():
    if "user" not in session:
        return "Access Restricted. Please login first.", 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM students WHERE deleted_at IS NULL")
    students = cursor.fetchall()
    cursor.execute("SELECT * FROM users WHERE deleted_at IS NULL")
    users = cursor.fetchall()
    conn.close()

    return render_template(
        "home.html",
        students=students,
        users=users,
        role=session["role"],
        username=session["user"]
    )

# Adding student
@app.route("/form", methods=["GET", "POST"])
def form():
    if "user" not in session:
        return "Access Restricted. Please login first.", 401
    if request.method == "POST":
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        phone_number = request.form["phone_number"]
        email = request.form["email"]

        if not re.fullmatch(r"\d{10}", phone_number):
            return "Phone number must contain exactly 10 digits."

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO students(first_name,last_name,phone_number,email)
        VALUES(?,?,?,?)
        """, (first_name,last_name,phone_number,email))
        conn.commit()
        conn.close()
        return redirect("/home")
    return render_template("form.html")

# Delete student
@app.route("/delete/<int:id>")
def delete(id):
    if "user" not in session:
        return "Access Restricted. Please login first.", 401

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM students WHERE id=?",(id,))
    student = cursor.fetchone()

    if student is None:
        conn.close()
        return "Student Not Found"
    if (session["role"] != "admin" and student["email"] != session["email"]):
        conn.close()
        return "Access Restricted"
    
    cursor.execute("""UPDATE students SET deleted_at = CURRENT_TIMESTAMP,
                   updated_at = CURRENT_TIMESTAMP WHERE id=?""",(id,))
    conn.commit()
    conn.close()
    return redirect("/home")

# Deleting user
@app.route("/delete-user/<int:id>")
def delete_user(id):
    if "user" not in session:
        return redirect("/login")

    if session.get("role") != "admin":
        return "Access Denied", 403

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET deleted_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (id,))

    conn.commit()
    conn.close()

    return redirect("/home")

# Editing student
@app.route("/edit/<int:id>", methods=["GET","POST"])
def edit(id):
    if "user" not in session:
        return "Access Restricted. Please login first.", 401

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM students WHERE id=? AND deleted_at IS NULL",(id,))
    student = cursor.fetchone()
    
    if student is None:
        conn.close()
        return "Student Not Found"

    if (session["role"] != "admin" and student["email"] != session["email"]):
        conn.close()
        return "Access Restricted"

    if request.method=="POST":
        first_name=request.form["first_name"]
        last_name=request.form["last_name"]
        phone_number=request.form["phone_number"]
        email=request.form["email"]

        if not re.fullmatch(r"\d{10}", phone_number):
            return "Phone number must contain exactly 10 digits."
        
        cursor.execute("""UPDATE students SET first_name=?,last_name=?,phone_number=?,email=?,
        updated_at=CURRENT_TIMESTAMP WHERE id=? """,
        (first_name,last_name,phone_number,email,id))

        conn.commit()
        conn.close()
        return redirect("/home")
    conn.close()
    return render_template(
        "edit.html",
        student=student
    )
    
    # Editing User
@app.route("/edit-user/<int:id>", methods=["GET", "POST"])
def edit_user(id):
    if "user" not in session:
        return redirect("/login")

    if session.get("role") != "admin":
        return "Access Denied", 403

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        phone_number = request.form["phone_number"]
        role = request.form["role"]

        cursor.execute("""
            UPDATE users
            SET username = ?,
                email = ?,
                phone_number = ?,
                role = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (username, email, phone_number, role, id))

        conn.commit()
        conn.close()

        return redirect("/home")

    cursor.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (id,))

    user = cursor.fetchone()

    conn.close()

    return render_template(
        "edit_user.html",
        user=user
    )
    
# logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# deleted students
@app.route("/deleted")
def deleted_students():

    if session["role"] != "admin":
        return "Access Restricted"

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM students
    WHERE deleted_at IS NOT NULL
    """)

    students = cursor.fetchall()
    conn.close()

    return render_template(
        "deleted.html",
        students=students
    )
# deleted users
@app.route("/deleted-users")
def deleted_users():

    if "user" not in session:
        return "Access Restricted"

    if session["role"] != "admin":
        return "Access Restricted"

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM users
        WHERE deleted_at IS NOT NULL
    """)

    users = cursor.fetchall()

    conn.close()

    return render_template(
        "deleted_users.html",
        users=users
    )
# restoring the del student 
@app.route("/restore/<int:id>")
def restore(id):

    if "user" not in session:
        return "Access Restricted"

    if session["role"] != "admin":
        return "Access Restricted"

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    UPDATE students
    SET
        deleted_at = NULL,
        updated_at = CURRENT_TIMESTAMP
    WHERE id=?
    """,(id,))

    conn.commit()
    conn.close()

    return redirect("/deleted")

# restoring the del user 
@app.route("/restore-user/<int:id>")
def restore_user(id):

    if "user" not in session:
        return "Access Restricted"

    if session["role"] != "admin":
        return "Access Restricted"

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET deleted_at = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (id,))

    conn.commit()
    conn.close()

    return redirect("/home")

if __name__=="__main__":
    app.run(debug=True)
    
 