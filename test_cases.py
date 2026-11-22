"""Test cases from report chapter 6 (UTC1, UTC2, ITC1, ITC2) plus checks for every module.

Needs a running MySQL server (uses a throw-away database `botnet_db_test`).
Run:  python test_cases.py
"""
import io
import os
import unittest

os.environ["DB_NAME"] = "botnet_db_test"          # must be set before importing app

import mysql.connector                             # noqa: E402
import pandas as pd                                # noqa: E402

import app as botnet                               # noqa: E402
from features import FEATURES, LABEL, SAMPLE_BENIGN, SAMPLE_BOTNET   # noqa: E402

USER = dict(username="Tester", email="tester@example.com", phone="9876543210", address="12 Test Street",
            password="secret123", confirm_password="secret123")


class BotnetApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        botnet.app.config["TESTING"] = True

    def setUp(self):
        conn = botnet.get_db(); cur = conn.cursor()
        cur.execute("DELETE FROM users"); conn.commit(); cur.close(); conn.close()
        self.c = botnet.app.test_client()

    def tearDown(self):
        for f in os.listdir(botnet.UPLOAD_FOLDER):
            if f.startswith("u") and f.endswith("_test.csv"):
                os.remove(os.path.join(botnet.UPLOAD_FOLDER, f))

    def register_and_login(self):
        self.c.post("/registration", data=USER)
        return self.c.post("/login", data=dict(email=USER["email"], password=USER["password"]))

    # --- UTC1: Data set feature / label extraction
    def test_UTC1_feature_label_extraction(self):
        df = pd.read_csv(botnet.DATASET_PATH)
        X, y = df[FEATURES], df[LABEL]
        self.assertEqual(X.shape[1], 17)
        self.assertEqual(len(X), len(y))
        self.assertEqual(set(y.unique()), {0, 1})

    # --- UTC2: Register / login (details stored in database, login success or fail)
    def test_UTC2_register_login(self):
        r = self.c.post("/registration", data=USER)
        self.assertEqual(r.status_code, 302)
        conn = botnet.get_db(); cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email=%s", (USER["email"],)); row = cur.fetchone()
        cur.close(); conn.close()
        self.assertIsNotNone(row)
        self.assertEqual((row["username"], row["phone"], row["address"]), ("Tester", "9876543210", "12 Test Street"))
        self.assertNotEqual(row["password"], USER["password"])                 # stored hashed
        self.assertEqual(self.c.post("/login", data=dict(email=USER["email"], password=USER["password"])).status_code, 302)
        bad = self.c.post("/login", data=dict(email=USER["email"], password="wrong"))
        self.assertIn(b"Invalid email or password", bad.data)

    def test_registration_validation(self):
        r = self.c.post("/registration", data={**USER, "confirm_password": "different"})
        self.assertIn(b"Passwords do not match", r.data)
        self.c.post("/registration", data=USER)
        r = self.c.post("/registration", data=USER)
        self.assertIn(b"already registered", r.data)                           # duplicate email
        r = self.c.post("/registration", data={**USER, "email": "bad-email"})
        self.assertIn(b"valid email", r.data)

    def test_protected_routes_require_login(self):
        for path in ("/upload", "/viewdata", "/algo", "/prediction"):
            self.assertEqual(self.c.get(path).status_code, 302, path)

    # --- File management
    def test_upload_flow(self):
        self.register_and_login()
        r = self.c.post("/upload", data={"file": (io.BytesIO(b"a,b\n1,2\n3,\n"), "test.csv")},
                        content_type="multipart/form-data")
        self.assertEqual(r.status_code, 302)
        page = self.c.get("/viewdata").data
        self.assertIn(b"missing after imputation", page)
        self.assertIn(b"SimpleImputer", page)
        r = self.c.post("/upload", data={"file": (io.BytesIO(b"x"), "notes.txt")}, content_type="multipart/form-data")
        self.assertIn(b"Only .csv", r.data)
        r = self.c.post("/upload", data={}, content_type="multipart/form-data")
        self.assertIn(b"No file selected", r.data)
        r = self.c.post("/upload", data={"file": (io.BytesIO(b""), "test.csv")}, content_type="multipart/form-data")
        self.assertIn(b"Could not read", r.data)                               # read errors trapped

    def test_viewdata_sample_with_text_columns(self):
        self.register_and_login()
        with open("sample_upload.csv", "rb") as fh:
            self.c.post("/upload", data={"file": (io.BytesIO(fh.read()), "test.csv")}, content_type="multipart/form-data")
        page = self.c.get("/viewdata").data
        self.assertIn(b"LabelEncoder", page)
        self.assertIn(b"icmp", page)

    # --- Model selection
    def test_algo_page(self):
        self.register_and_login()
        self.assertEqual(set(botnet.MODEL_ACCURACY),
                         {"Logistic Regression", "Naive Bayes", "KNN", "Random Forest", "Gradient Boosting"})
        r = self.c.post("/algo", data={"model": "KNN"})
        self.assertIn(str(botnet.MODEL_ACCURACY["KNN"]).encode(), r.data)

    # --- ITC1 / ITC2: prediction
    def test_ITC1_ITC2_prediction(self):
        self.register_and_login()
        r = self.c.post("/prediction", data=SAMPLE_BENIGN)
        self.assertIn(b"Benign", r.data)
        self.assertIn(b"no action is required", r.data)
        r = self.c.post("/prediction", data=SAMPLE_BOTNET)
        self.assertIn(b"Malicious", r.data)
        self.assertIn(b"Isolate the device", r.data)

    def test_prediction_rejects_bad_input(self):
        self.register_and_login()
        for bad in ({**SAMPLE_BENIGN, "duration": "abc"}, {**SAMPLE_BENIGN, "src_bytes": "-5"},
                    {**SAMPLE_BENIGN, "protocol": "7"}):
            self.assertIn(b"Invalid input", self.c.post("/prediction", data=bad).data)


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2, exit=False)
    finally:
        conn = mysql.connector.connect(host=botnet.DB_HOST, port=botnet.DB_PORT, user=botnet.DB_USER,
                                       password=botnet.DB_PASSWORD)
        conn.cursor().execute("DROP DATABASE IF EXISTS botnet_db_test"); conn.close()
