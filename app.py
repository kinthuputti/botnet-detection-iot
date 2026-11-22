"""Hybrid ML-Based Botnet Detection System for IoT Networks  -  Flask application.

Modules:
  Authentication      /registration, /login      (MySQL `users` table)
  File management     /upload                    (saves to uploads/, loads with pd.read_csv)
  Data processing     data_processing.py         (SimpleImputer, LabelEncoder, train_test_split, KFold)
  Model selection     /algo                      (hard-coded accuracy dictionary, no on-the-fly training)
  Prediction          /prediction                (17 numeric inputs, Logistic Regression retrained on
                                                      cleaned_dataset.csv, "Benign" / "Malicious" + advice)
  Presentation        templates/ + df.to_html()  (Bootstrap)
"""
import os
import re
import uuid
from functools import wraps

import mysql.connector
import numpy as np
import pandas as pd
from flask import Flask, flash, redirect, render_template, request, session, url_for
from sklearn.preprocessing import LabelEncoder
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from data_processing import clean_dataframe, label_summary, load_csv
from features import FEATURE_INFO, FEATURES, LABEL, PROTOCOL_CODES, SAMPLE_BENIGN, SAMPLE_BOTNET
from model_utils import logistic_regression

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "cleaned_dataset.csv")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

# ----------------------------------------------------------------------------- app setup
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "secretkey")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024          # 25 MB
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# MySQL (XAMPP defaults: user "root", empty password)
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "3306"))
DB_USER = os.environ.get("DB_USER", "root")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
DB_NAME = os.environ.get("DB_NAME", "botnet_db")

# Pre-tested algorithms: name -> accuracy (%) from 5-fold cross-validation on cleaned_dataset.csv.
# Hard-coded on purpose: /algo only displays these, it never trains. Regenerate them with
# `python evaluate_models.py --write` after changing the dataset.
MODEL_ACCURACY = {
    "Logistic Regression": 98.8,
    "Naive Bayes": 89.13,
    "KNN": 98.68,
    "Random Forest": 98.87,
    "Gradient Boosting": 98.72,
}

ADVICE = {
    "Malicious": [
        "Isolate the device from the network (move it to a quarantine VLAN) to stop it spreading.",
        "Block the device's outbound traffic and the destination addresses it contacts at the gateway/firewall.",
        "Capture the flow (PCAP) for forensic analysis and notify the network administrator.",
        "Change the device credentials, then update or re-flash its firmware from a trusted image.",
    ],
    "Benign": [
        "This traffic matches normal IoT behaviour - no action is required.",
        "Keep monitoring; unusual spikes in packet rate or contacted ports would be a warning sign.",
    ],
}


# ----------------------------------------------------------------------------- database (MySQL)
def get_db():
    return mysql.connector.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD,
                                   database=DB_NAME)


def init_db():
    """Create the database and the users table if they do not exist yet."""
    conn = mysql.connector.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD)
    cur = conn.cursor()
    cur.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4")
    cur.execute(f"USE `{DB_NAME}`")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(80)  NOT NULL,
            email    VARCHAR(120) NOT NULL UNIQUE,
            phone    VARCHAR(20)  NOT NULL,
            address  VARCHAR(255) NOT NULL,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
    conn.commit()
    cur.close()
    conn.close()


try:
    init_db()
except mysql.connector.Error as exc:                      # pragma: no cover
    raise SystemExit(f"\nCould not connect to MySQL at {DB_HOST}:{DB_PORT} as '{DB_USER}': {exc}\n"
                     "Start MySQL (e.g. the XAMPP control panel -> MySQL -> Start) and check the DB_* "
                     "settings, then run again.\n")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# ----------------------------------------------------------------------------- public pages
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


# ----------------------------------------------------------------------------- authentication
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@app.route("/registration", methods=["GET", "POST"])
def registration():
    form = {}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in ("username", "email", "phone", "address")}
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        phone_digits = re.sub(r"[\s\-+()]", "", form["phone"])
        error = None
        if not all(form.values()) or not password:
            error = "Please fill in every field."
        elif not EMAIL_RE.match(form["email"]):
            error = "Enter a valid email address."
        elif not phone_digits.isdigit() or not 7 <= len(phone_digits) <= 15:
            error = "Enter a valid phone number."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif password != confirm:                              # password confirmation
            error = "Passwords do not match."
        if not error:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE email = %s", (form["email"].lower(),))
            if cur.fetchone():                                 # does the email already exist?
                error = "That email is already registered."
            else:
                cur.execute("INSERT INTO users (username, email, phone, address, password) "
                            "VALUES (%s, %s, %s, %s, %s)",
                            (form["username"], form["email"].lower(), form["phone"], form["address"],
                             generate_password_hash(password)))
                conn.commit()
            cur.close()
            conn.close()
        if error:
            flash(error, "danger")
        else:
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("registration.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, username, password FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if user and check_password_hash(user["password"], password):   # compare to stored credentials
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash(f"Welcome, {user['username']}!", "success")
            return redirect(url_for("upload"))
        flash("Invalid email or password.", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


# ----------------------------------------------------------------------------- file management
def my_files():
    prefix = f"u{session['user_id']}_"
    return sorted((f for f in os.listdir(UPLOAD_FOLDER) if f.startswith(prefix)), reverse=True)


def shown_name(stored):
    return stored.split("_", 2)[-1]


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("file")                       # check request.files
        if file is None or file.filename == "":
            flash("No file selected. Please choose a CSV file.", "danger")
        elif not file.filename.lower().endswith(".csv"):
            flash("Only .csv files are supported.", "danger")
        else:
            stored = f"u{session['user_id']}_{uuid.uuid4().hex[:6]}_{secure_filename(file.filename)}"
            path = os.path.join(app.config["UPLOAD_FOLDER"], stored)
            file.save(path)                                    # save to uploads/
            try:
                df = pd.read_csv(path)                         # import into memory
                if df.empty:
                    raise ValueError("the file has no rows")
            except Exception as exc:                           # read errors are trapped
                os.remove(path)
                flash(f"Could not read that file: {exc}", "danger")
            else:
                session["dataset"] = stored
                flash(f"Uploaded {shown_name(stored)}: {df.shape[0]} rows x {df.shape[1]} columns.", "success")
                return redirect(url_for("viewdata"))
    return render_template("upload.html", files=[(f, shown_name(f)) for f in my_files()])


# ----------------------------------------------------------------------------- view data
@app.route("/viewdata")
@login_required
def viewdata():
    choice = request.args.get("file") or session.get("dataset")
    path = None
    if choice == "__cleaned__":
        path, title = DATASET_PATH, "cleaned_dataset.csv (built-in training data)"
    elif choice and choice in my_files():
        path, title = os.path.join(UPLOAD_FOLDER, choice), shown_name(choice)
    if path is None:
        return render_template("viewdata.html", table=None, files=[(f, shown_name(f)) for f in my_files()])

    df = load_csv(path)
    clean, info = clean_dataframe(df)                            # imputation + label encoding
    css = "table table-striped table-hover table-bordered table-sm"
    return render_template(
        "viewdata.html", title=title, selected=choice, files=[(f, shown_name(f)) for f in my_files()],
        info=info, labels=label_summary(clean),
        missing=df.isna().sum()[df.isna().sum() > 0].to_dict(),
        table=df.head(50).round(4).to_html(classes=css, index=False, na_rep="NaN"),
        clean_table=clean.head(20).round(4).to_html(classes=css, index=False))


# ----------------------------------------------------------------------------- model selection
@app.route("/algo", methods=["GET", "POST"])
@login_required
def algo():
    selected = request.form.get("model") if request.method == "POST" else None
    if selected not in MODEL_ACCURACY:
        selected = None
    best = max(MODEL_ACCURACY, key=MODEL_ACCURACY.get)
    return render_template("algo.html", models=MODEL_ACCURACY, selected=selected, best=best,
                           score=MODEL_ACCURACY.get(selected))


# ----------------------------------------------------------------------------- prediction
@app.route("/prediction", methods=["GET", "POST"])
@login_required
def prediction():
    values = dict(SAMPLE_BENIGN)
    result = None
    if request.method == "POST":
        try:
            values = {f: float(request.form.get(f, "")) for f in FEATURES}
            if not all(np.isfinite(v) and v >= 0 for v in values.values()):
                raise ValueError("every value must be a non-negative number")
            if values["protocol"] not in PROTOCOL_CODES.values():
                raise ValueError("protocol must be 0 (ICMP), 1 (TCP) or 2 (UDP)")
        except ValueError as exc:
            flash(f"Invalid input: {exc}.", "danger")
        else:
            vector = pd.DataFrame([values], columns=FEATURES)       # the seventeen inputs -> feature vector
            df = pd.read_csv(DATASET_PATH)                          # reload cleaned_dataset.csv
            X = df[FEATURES]
            y = LabelEncoder().fit_transform(df[LABEL])
            model = logistic_regression().fit(X, y)                 # retrain Logistic Regression on all data
            pred = int(model.predict(vector)[0])
            proba = float(model.predict_proba(vector)[0][1])
            label = "Malicious" if pred == 1 else "Benign"
            result = {"label": label, "probability": round(proba * 100, 1), "advice": ADVICE[label]}
    shown = {k: (str(int(v)) if float(v).is_integer() else str(round(float(v), 6))) for k, v in values.items()}
    return render_template("prediction.html", info=FEATURE_INFO, values=values, shown=shown, result=result,
                           sample_benign=SAMPLE_BENIGN, sample_botnet=SAMPLE_BOTNET)


@app.errorhandler(413)
def file_too_large(_):
    flash("That file is too large (25 MB maximum).", "danger")
    return redirect(url_for("upload"))


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
