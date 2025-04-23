from flask import Flask, render_template, request, redirect, url_for, session
from flask import flash
from datetime import datetime, timedelta
import string
from email.message import EmailMessage
import sqlite3
import bcrypt
import random
from flask_mail import Mail, Message
import math
from functools import wraps

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# Mail configuration
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER")

with app.app_context():
    for rule in app.url_map.iter_rules():
        print(rule.endpoint)

# Identifiants fictifs (used only for demo — now using DB)
USERNAME = "NOUHAILA"
PASSWORD = "HAJJAJE@nouhaila2004"


# ➕ Initialiser la base de données une seule fois
def init_db():
    with sqlite3.connect("users.db") as conn:
        c = conn.cursor()
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password BLOB NOT NULL
            )
        """
        )
        conn.commit()


init_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            flash("Veuillez vous connecter pour accéder à cette page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


@app.route("/")
def home():
    if "username" in session:
        return render_template("home.html", username=session["username"])
    return render_template("landing.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    print("La fonction login() a été appelée")
    if "username" in session:
        return redirect(url_for("home"))

    # Initialiser les valeurs dans la session
    if "login_attempts" not in session:
        session["login_attempts"] = 0
    if "lock_until" not in session:
        session["lock_until"] = None

    now = datetime.now()

    # Vérifier si le bouton est temporairement bloqué
    if session["lock_until"]:
        lock_time = datetime.fromisoformat(session["lock_until"])
        if now < lock_time:
            seconds_remaining = int((lock_time - now).total_seconds())
            return render_template(
                "login.html",
                error=f"Trop de tentatives. Réessayez dans {seconds_remaining} secondes.",
                lock=seconds_remaining,
            )

    if request.method == "POST":
        username_input = request.form["username"].strip()
        password_input = request.form["password"].strip()

        # Connexion à la base
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username_input,))
        result = c.fetchone()
        conn.close()

        if result is not None:
            hashed_password = result[0]
            if bcrypt.checkpw(password_input.encode(), hashed_password):
                session["username"] = username_input
                session["login_attempts"] = 0
                session["lock_until"] = None
                return redirect(url_for("home"))

        # Si mot de passe incorrect ou utilisateur non trouvé
        session["login_attempts"] += 1
        delays = [15, 30, 60]
        delay_index = min(session["login_attempts"] - 1, len(delays) - 1)
        delay_seconds = delays[delay_index]

        session["lock_until"] = (now + timedelta(seconds=delay_seconds)).isoformat()

        return render_template(
            "login.html",
            error="Identifiants incorrects. Vous êtes temporairement bloqué.",
            lock=delay_seconds,
        )

    return render_template("login.html", error=None, lock=0)






@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "username" in session:
        return redirect(url_for("home"))
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"].strip()

        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        try:
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, hashed_pw),
            )
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError as e:
            error_msg = "Nom d'utilisateur ou email déjà utilisé"
            return render_template("signup.html", error=error_msg)

    return render_template("signup.html", error=None)


# -------------------------------------------- Forget Password Code ---------------------------------------------

app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT"))
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")

mail = Mail(app)



# kangeneriw random password howa  lpassword jdid
def generate_password(length=10):
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    print("-------------call forgot passwoprd-------------------")
    if "username" in session:
        return redirect(url_for("home"))
    if request.method == "POST":
        email = request.form["email"].strip()

        # kantconetaw m3a database
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE email = ?", (email,))
        result = c.fetchone()
        
        if result:
            # kan3generiw random password
            new_password = generate_password()
            hashed_pw = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())

            # kanbdlo lpassword l9dim
            c.execute(
                "UPDATE users SET password = ? WHERE email = ?", (hashed_pw, email)
            )
            conn.commit()
            conn.close()

            # kansifto lpassword jdid l email
            msg = Message(
                "Votre nouveau mot de passe",
                sender=app.config["MAIL_USERNAME"],
                recipients=[email],
            )
            msg.body = f"Bonjour {result[0]},\n\nVoici votre nouveau mot de passe temporaire : {new_password}\n\n"
            mail.send(msg)

            return redirect(url_for("login"))
        else:
            conn.close()
            return render_template("forgot_password.html", error="Email non trouvé.")

    return render_template("forgot_password.html", error=None)


# -------------------------------------------- Forget Password Code end ---------------------------------------------
# --------------------------------------------  calcule start ---------------------------------------------


def calcul_diffusion(x_A, D_AB0, D_BA0, q_A, q_B, r_A, r_B, a_AB, a_BA, T, D_exp):
    try:
        x_B = 1 - x_A
        y_A = r_A ** (1 / 3)
        y_B = r_B ** (1 / 3)
        phi_A = (x_A * y_A) / (x_A * y_A + (1 - x_A) * y_B)
        phi_B = ((1 - x_A) * y_B) / (x_A * y_A + (1 - x_A) * y_B)
        theta_A = (x_A * q_A) / (x_A * q_A + x_B * q_B)
        theta_B = (x_B * q_B) / (x_A * q_A + x_B * q_B)
        tau_AB = math.exp(-a_AB / T)
        tau_BA = math.exp(-a_BA / T)
        theta_AA = (theta_A * 1) / (theta_A * 1 + theta_B * tau_BA)
        theta_BB = (theta_B * 1) / (theta_A * tau_AB + theta_B * 1)
        theta_AB = (theta_A * tau_AB) / (theta_A * tau_AB + theta_B * tau_BA)
        theta_BA = (theta_B * tau_BA) / (theta_A * 1 + theta_B * tau_BA)
        ln_D_AB = (
            (x_A * math.log(D_BA0) + (1 - x_A) * math.log(D_AB0))
            + 2
            * (x_A * math.log(x_A / phi_A) + (1 - x_A) * math.log((1 - x_A) / phi_B))
            + 2
            * x_A
            * (1 - x_A)
            * (
                (phi_A / x_A) * (1 - (y_A / y_B))
                + (phi_B / (1 - x_A)) * (1 - (y_B / y_A))
            )
            + x_A
            * q_B
            * (
                (1 - theta_AB * 2) * math.log(tau_AB)
                + (1 - theta_AA * 2) * tau_BA * math.log(tau_BA)
            )
            + (1 - x_A)
            * q_A
            * (
                (1 - theta_BA * 2) * math.log(tau_BA)
                + (1 - theta_BB * 2) * tau_AB * math.log(tau_AB)
            )
        )
        D_AB = math.exp(ln_D_AB)
        error = 1.6
        return D_AB, error
    except ValueError:
        return None, None




@app.route("/calculator/form")
@login_required
def calculator_form():
    fields = [
        {"label": "Mole fraction of A (x_A)", "name": "x_A", "value": "0.25"},
        {
            "label": "Base diffusion coefficient D_AB^0",
            "name": "D_AB0",
            "value": "2.1e-5",
        },
        {
            "label": "Base diffusion coefficient D_BA^0",
            "name": "D_BA0",
            "value": "2.67e-5",
        },
        {"label": "Volume parameter q_A", "name": "q_A", "value": "1.432"},
        {"label": "Volume parameter q_B", "name": "q_B", "value": "1.4"},
        {"label": "Parameter r_A", "name": "r_A", "value": "1.4311"},
        {"label": "Parameter r_B", "name": "r_B", "value": "0.92"},
        {"label": "Interaction parameter a_AB", "name": "a_AB", "value": "-10.7575"},
        {"label": "Interaction parameter a_BA", "name": "a_BA", "value": "194.5302"},
        {"label": "Temperature T (K)", "name": "T", "value": "313.13"},
        {
            "label": "Experimental diffusion coefficient (cm²/s)",
            "name": "D_exp",
            "value": "1.33e-5",
        },
    ]
    return render_template("calculator_form.html", fields=fields)


@app.route("/calculator/result", methods=["POST"])
@login_required
def calculator_result():
    try:
        x_A = float(request.form["x_A"].replace(",", "."))
        D_AB0 = float(request.form["D_AB0"])
        D_BA0 = float(request.form["D_BA0"])
        q_A = float(request.form["q_A"])
        q_B = float(request.form["q_B"])
        r_A = float(request.form["r_A"])
        r_B = float(request.form["r_B"])
        a_AB = float(request.form["a_AB"])
        a_BA = float(request.form["a_BA"])
        T = float(request.form["T"])
        D_exp = float(request.form["D_exp"])

        D_AB, error = calcul_diffusion(
            x_A, D_AB0, D_BA0, q_A, q_B, r_A, r_B, a_AB, a_BA, T, D_exp
        )
        if D_AB is None:
            raise ValueError("Invalid input values.")

        return render_template(
            "calculator_result.html", D_AB=f"{D_AB:.4e}", error=error
        )
    except (ValueError, KeyError):
        return redirect(url_for("calculator_home"))


# -------------------------------------------- calcule end ---------------------------------------------


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
