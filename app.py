
import os
import sqlite3
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, g
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, instance_relative_config=True)

os.makedirs(app.instance_path, exist_ok=True)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "change-this-development-secret"
)
app.config["DATABASE"] = os.path.join(
    app.instance_path, "find_doctor.db"
)

csrf = CSRFProtect(app)


# ---------------- DATABASE ----------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()

    db.executescript("""
        CREATE TABLE IF NOT EXISTS hospitals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            phone TEXT NOT NULL,
            address TEXT NOT NULL,
            city TEXT NOT NULL,
            verified INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS doctors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hospital_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            specialization TEXT NOT NULL,
            qualification TEXT,
            timings TEXT NOT NULL,
            available INTEGER DEFAULT 1,
            FOREIGN KEY(hospital_id)
                REFERENCES hospitals(id) ON DELETE CASCADE
        );
    """)

    db.commit()


# ---------------- COMMON ----------------

@app.context_processor
def inject_csrf():
    from flask_wtf.csrf import generate_csrf
    return {"csrf_token": generate_csrf}


def hospital_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if "hospital_id" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))
        return view(**kwargs)
    return wrapped_view


# ---------------- HOME PAGE ----------------

@app.route("/")
def home():
    query = request.args.get("q", "").strip()
    language = request.args.get("lang", "en")

    db = get_db()

    if query:
        doctors = db.execute("""
            SELECT doctors.*, hospitals.name AS hospital_name,
                   hospitals.phone, hospitals.address, hospitals.city
            FROM doctors
            JOIN hospitals ON doctors.hospital_id = hospitals.id
            WHERE doctors.name LIKE ?
               OR doctors.specialization LIKE ?
               OR hospitals.name LIKE ?
               OR hospitals.city LIKE ?
            ORDER BY hospitals.verified DESC, doctors.name
        """, tuple([f"%{query}%"] * 4)).fetchall()
    else:
        doctors = db.execute("""
            SELECT doctors.*, hospitals.name AS hospital_name,
                   hospitals.phone, hospitals.address, hospitals.city
            FROM doctors
            JOIN hospitals ON doctors.hospital_id = hospitals.id
            ORDER BY hospitals.verified DESC, doctors.name
        """).fetchall()

    return render_template(
        "index.html",
        doctors=doctors,
        query=query,
        lang=language
    )


# ---------------- HOSPITAL REGISTRATION ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        city = request.form.get("city", "").strip()

        if not all([name, email, password, phone, address, city]):
            flash("Please complete all fields.", "error")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must have at least 8 characters.", "error")
            return redirect(url_for("register"))

        db = get_db()

        try:
            db.execute("""
                INSERT INTO hospitals
                (name, email, password, phone, address, city)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                name, email, generate_password_hash(password),
                phone, address, city
            ))
            db.commit()

            flash(
                "Registration successful. Awaiting hospital verification.",
                "success"
            )
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("This email is already registered.", "error")

    return render_template("register.html")


# ---------------- HOSPITAL LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        hospital = get_db().execute(
            "SELECT * FROM hospitals WHERE email = ?",
            (email,)
        ).fetchone()

        if hospital and check_password_hash(
            hospital["password"], password
        ):
            session.clear()
            session["hospital_id"] = hospital["id"]
            session["hospital_name"] = hospital["name"]

            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


# ---------------- HOSPITAL DASHBOARD ----------------

@app.route("/dashboard")
@hospital_required
def dashboard():
    db = get_db()

    doctors = db.execute("""
        SELECT * FROM doctors
        WHERE hospital_id = ?
        ORDER BY name
    """, (session["hospital_id"],)).fetchall()

    hospital = db.execute("""
        SELECT * FROM hospitals WHERE id = ?
    """, (session["hospital_id"],)).fetchone()

    return render_template(
        "dashboard.html",
        doctors=doctors,
        hospital=hospital
    )


# ---------------- ADD DOCTOR ----------------

@app.route("/add-doctor", methods=["POST"])
@hospital_required
def add_doctor():
    name = request.form.get("name", "").strip()
    specialization = request.form.get(
        "specialization", ""
    ).strip()
    qualification = request.form.get(
        "qualification", ""
    ).strip()
    timings = request.form.get("timings", "").strip()

    if not all([name, specialization, timings]):
        flash("Please enter doctor name, specialization and timings.", "error")
        return redirect(url_for("dashboard"))

    db = get_db()

    db.execute("""
        INSERT INTO doctors
        (hospital_id, name, specialization, qualification, timings)
        VALUES (?, ?, ?, ?, ?)
    """, (
        session["hospital_id"],
        name,
        specialization,
        qualification,
        timings
    ))

    db.commit()

    flash("Doctor added successfully.", "success")
    return redirect(url_for("dashboard"))


# ---------------- UPDATE AVAILABILITY ----------------

@app.route("/toggle-doctor/<int:doctor_id>", methods=["POST"])
@hospital_required
def toggle_doctor(doctor_id):
    db = get_db()

    doctor = db.execute("""
        SELECT * FROM doctors
        WHERE id = ? AND hospital_id = ?
    """, (doctor_id, session["hospital_id"])).fetchone()

    if doctor:
        db.execute("""
            UPDATE doctors SET available = ?
            WHERE id = ? AND hospital_id = ?
        """, (
            0 if doctor["available"] else 1,
            doctor_id,
            session["hospital_id"]
        ))
        db.commit()

    return redirect(url_for("dashboard"))


# ---------------- LOGOUT ----------------

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


# ---------------- START APPLICATION ----------------

with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=True)
