# Hybrid ML-Based Botnet Detection System for IoT Networks

Flask + MySQL web application implementing the modules in chapter 5 of the project report.

| Report section | Where it lives |
|---|---|
| 5.1 Authentication – `/registration`, `/login`, MySQL `users` table | `app.py`, `templates/registration.html`, `login.html` |
| 5.2 File management – `/upload` saves to `uploads/`, `pd.read_csv()`, try/except + `flash()` | `app.py`, `templates/upload.html` |
| 5.3 Data processing – `SimpleImputer`, `LabelEncoder`, `train_test_split`, `KFold` | `data_processing.py` |
| 5.4 Model selection – `/algo`, hard-coded accuracy dictionary, no on-the-fly training | `MODEL_ACCURACY` in `app.py`, `templates/algo.html` |
| 5.5 Prediction – `/prediction`, 17 numeric inputs, reloads `cleaned_dataset.csv`, retrains Logistic Regression, "Benign"/"Malicious" + advice | `app.py`, `templates/prediction.html` |
| 5.6 Presentation – templates for index, about, registration, login, upload, viewdata, algo, prediction; `df.to_html()`; Bootstrap | `templates/` |
| Chapter 6 test cases (UTC1, UTC2, ITC1, ITC2 + more) | `test_cases.py` |

## Run it (Windows + XAMPP, as in the report)
1. Open the **XAMPP Control Panel** and start **MySQL** (default user `root`, empty password).
2. In the project folder:
   ```
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   python app.py
   ```
3. Open http://127.0.0.1:5000, **Register**, **Login**, then use Upload → View Data → Algorithms → Prediction.

The database `botnet_db` and its `users` table are created automatically (`database.sql` is provided if you prefer
importing it in phpMyAdmin). Different MySQL settings? Set `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`.

## Try it
* **Upload** `sample_upload.csv` – a raw file with missing values and text columns. **View Data** shows it before and after
  imputation / label encoding.
* **Prediction** has *Fill benign sample* / *Fill botnet sample* buttons for the 17 inputs.
* **Algorithms** lists Logistic Regression, Naive Bayes, KNN, Random Forest and Gradient Boosting with their stored accuracy.
* `python test_cases.py` runs the test cases (needs MySQL running; uses a temporary `botnet_db_test` database).

## About the data (please read)
The report uses UNSW-NB15, Bot-IoT and CICIoT2023-style data, which are not bundled. `build_dataset.py` generates a
**synthetic** stand-in (benign IoT traffic plus DDoS floods, port scans, C&C beaconing and data exfiltration) with 17 flow
features, written to `cleaned_dataset.csv`. All models score ~99% on it except Naive Bayes, which says little about real-world
performance. To use real data, map its columns to the 17 names in `features.py`, add a 0/1 `label` (0 = Benign,
1 = Malicious), save it as `cleaned_dataset.csv`, then run `python evaluate_models.py --write` to refresh the `/algo` scores.

Protocol codes follow `LabelEncoder`'s alphabetical order: ICMP = 0, TCP = 1, UDP = 2.

## Notes
* Passwords are stored hashed (not plain text). There is no CSRF protection or HTTPS; run it as a local/demo app, set
  `SECRET_KEY`, and add those before any real deployment.
* `/prediction` retrains Logistic Regression on all of `cleaned_dataset.csv` for each request, as the report describes. This takes
  a fraction of a second at this dataset size. Log-scaling and standardisation (the report's "normalization") are applied first.
* Detection only: the application analyses traffic features; it never generates or sends network traffic.
