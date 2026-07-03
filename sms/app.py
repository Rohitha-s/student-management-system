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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    
    ''' 
    cursor.execute("""
    ALTER TABLE students
    ADD COLUMN deleted_at INTEGER DEFAULT 0;
    """) 
    '''
      
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
    cursor.execute("SELECT * FROM users WHERE email=?",(email,))
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
    cursor.execute("SELECT * FROM students WHERE is_deleted = 0")
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
    cursor.execute("""UPDATE students SET deleted_at=1,
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
        role=request.form["role"]
        
        hashed_password=generate_password_hash(password)

        conn=get_db_connection()
        cursor=conn.cursor()
        # Check email exists
        cursor.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        )
        existing_user=cursor.fetchone()

        if existing_user:
            conn.close()
            return render_template(
                "signup.html",
                error="Email already exists. Please use another email.")
            
        cursor.execute("""
        INSERT INTO users(username,email,password,role)
        VALUES(?,?,?,?)
        """,(username,email,hashed_password,role))
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
    cursor.execute("SELECT * FROM students WHERE deleted_at = 0")
    students = cursor.fetchall()
    conn.close()

    return render_template(
        "home.html",
        students=students,
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
        email = request.form["email"]

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO students(first_name,last_name,email)
        VALUES(?,?,?)
        """, (first_name,last_name,email))
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
    
    cursor.execute("""UPDATE students SET deleted_at = 1,
                   updated_at = CURRENT_TIMESTAMP WHERE id=?""",(id,))
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
    cursor.execute("SELECT * FROM students WHERE id=? AND is_deleted=0",(id,))
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
        email=request.form["email"]

        cursor.execute("""UPDATE students SET first_name=?,last_name=?,email=?,
        updated_at=CURRENT_TIMESTAMP WHERE id=? """,
        (first_name,last_name,email,id))

        conn.commit()
        conn.close()
        return redirect("/home")
    conn.close()
    return render_template(
        "edit.html",
        student=student
    )

# logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# deleted records 
@app.route("/deleted")
def deleted_students():

    if session["role"] != "admin":
        return "Access Restricted"

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM students
    WHERE deleted_at=1
    """)

    students = cursor.fetchall()
    conn.close()

    return render_template(
        "deleted.html",
        students=students
    )
    
# restoring the del data
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
        deleted_at = 0,
        updated_at = CURRENT_TIMESTAMP
    WHERE id=?
    """,(id,))

    conn.commit()
    conn.close()

    return redirect("/deleted")


if __name__=="__main__":
    app.run(debug=True)
    
 