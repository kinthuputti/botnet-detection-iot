# Hybrid ML-Based Botnet Detection System for IoT Networks

A Flask + MySQL web application that classifies IoT network flows as **Benign** or **Malicious** and suggests how to respond.

## Features
- **Registration and login** – accounts stored in a MySQL `users` table (username, email, phone, address, password).
- **Upload** – upload a CSV of network traffic; it is saved to `uploads/` and loaded with pandas.
- **View Data** – preview the file, then see it after pre-processing (missing values imputed with `SimpleImputer`, text columns converted with `LabelEncoder`).
- **Algorithms** – compare Logistic Regression, Naive Bayes, KNN, Random Forest and Gradient Boosting by stored accuracy (5-fold cross-validation).
- **Prediction** – enter 17 numeric flow features; a Logistic Regression model trained on `cleaned_dataset.csv` returns Benign or Malicious with recommended actions.

## Project layout
| File / folder | Purpose |
|---|---|
| `app.py` | Flask routes: `/`, `/about`, `/registration`, `/login`, `/upload`, `/viewdata`, `/algo`, `/prediction` |
| `data_processing.py` | Imputation, label encoding, train/test split, k-fold |
| `model_utils.py` | Model definitions shared by the comparison and the predictor |
| `features.py` | The 17 input features and their descriptions |
| `build_dataset.py`, `dataset_generator.py` | Generate `cleaned_dataset.csv` and `sample_upload.csv` |
| `evaluate_models.py` | Computes the accuracy values used on the Algorithms page |
| `test_cases.py` | Automated tests |
| `templates/`, `static/` | Bootstrap pages and styles |

## Run it (Windows + XAMPP)
1. Open the **XAMPP Control Panel** and start **MySQL** (default user `root`, empty password).
2. In the project folder:
   ```
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   python app.py
   ```
3. Open http://127.0.0.1:5000, register, log in, then use Upload → View Data → Algorithms → Prediction.

The `botnet_db` database and `users` table are created automatically (`database.sql` is included if you prefer importing it in phpMyAdmin).
If MySQL runs on another port or has a password, set `DB_PORT`, `DB_HOST`, `DB_USER`, `DB_PASSWORD` or `DB_NAME` first, for example
`$env:DB_PORT="3307"` in PowerShell.

## Try it
- Upload `sample_upload.csv`, a raw file with missing values and text columns, then open **View Data**.
- On **Prediction**, use *Fill benign sample* / *Fill botnet sample*.
- `python test_cases.py` runs the tests (needs MySQL running; uses a temporary `botnet_db_test` database).

## About the data
The bundled dataset is **synthetic**. `build_dataset.py` generates benign IoT traffic plus DDoS floods, port scans, C&C beaconing and data
exfiltration with 17 flow features and writes `cleaned_dataset.csv`. Most models score about 99% on it (Naive Bayes is lower), which says
little about real-world performance. To use real data, map its columns to the names in `features.py`, add a 0/1 `label`
(0 = Benign, 1 = Malicious), save it as `cleaned_dataset.csv`, then run `python evaluate_models.py --write` to refresh the Algorithms scores.

Protocol codes follow `LabelEncoder`'s alphabetical order: ICMP = 0, TCP = 1, UDP = 2.

## Live demo (free hosting on Render)
The live demo stores users in SQLite instead of MySQL (set `DB_BACKEND=sqlite`), because free hosting has no database server. Everything else is identical.

1. Push this project to GitHub.
2. On [render.com](https://render.com): **New → Web Service**, connect the repository, choose the **Free** instance type, and set:
   - **Build command:** `pip install -r requirements.txt`
   - **Start command:** `gunicorn app:app --timeout 120`
3. Add these environment variables:

   | Key | Value |
   |---|---|
   | `DB_BACKEND` | `sqlite` |
   | `PYTHON_VERSION` | `3.12.7` |
   | `SECRET_KEY` | any long random string |
   | `DEMO_EMAIL` | `demo@botnet-demo.com` |
   | `DEMO_PASSWORD` | `Demo@12345` |

4. Deploy. The demo account above is created automatically at startup.

Free-tier behaviour: the app sleeps after 15 minutes without visits (the first request afterwards takes about a minute), and its
files, including registered users and uploads, are wiped whenever it restarts. The demo account is recreated each time.

## Notes
- Passwords are stored hashed. There is no CSRF protection or HTTPS, so treat this as a local/demo app and set `SECRET_KEY` before any real deployment.
- `/prediction` retrains Logistic Regression on all of `cleaned_dataset.csv` for each request. Log-scaling and standardisation are applied first.
- Detection only: the application analyses traffic features and never generates or sends network traffic.
