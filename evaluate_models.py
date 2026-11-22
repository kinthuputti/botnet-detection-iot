"""Pre-tests the five algorithms on cleaned_dataset.csv and prints the dictionary that is hard-coded in app.py.

Run:  python evaluate_models.py          (prints the dict)
      python evaluate_models.py --write  (also rewrites the MODEL_ACCURACY block in app.py)
"""
import re
import sys

import pandas as pd

from data_processing import kfold_accuracy, split_data
from features import FEATURES, LABEL
from model_utils import candidate_models

if __name__ == "__main__":
    df = pd.read_csv("cleaned_dataset.csv")
    X, y = df[FEATURES], df[LABEL]
    Xtr, Xte, ytr, yte = split_data(X, y)
    rows = {}
    for name, model in candidate_models().items():
        cv = kfold_accuracy(model, X, y, k=5)                       # 5-fold average accuracy
        holdout = model.fit(Xtr, ytr).score(Xte, yte)                # 80/20 hold-out, for reference
        rows[name] = round(cv * 100, 2)
        print(f"{name:20s} 5-fold CV: {cv*100:6.2f}%   hold-out: {holdout*100:6.2f}%")

    block = "MODEL_ACCURACY = {\n" + "".join(f'    "{k}": {v},\n' for k, v in rows.items()) + "}"
    print("\n" + block)
    if "--write" in sys.argv:
        src = open("app.py").read()
        new = re.sub(r"MODEL_ACCURACY = \{.*?\n\}", block, src, flags=re.S)
        open("app.py", "w").write(new)
        print("\napp.py updated.")
