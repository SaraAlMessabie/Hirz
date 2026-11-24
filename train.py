"""
Phase 3 - baseline model
  in : data/features.csv
  out: data/model.pkl   (model + feature list + threshold)
"""
import joblib
import numpy as np
import pandas as pd
import lightgbm as lgb
import shap
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             roc_auc_score, confusion_matrix)

THRESHOLD = 0.5          # tune from the sweep below

# ---------------------------------------------------------------- load
df = pd.read_csv("data/features.csv")
X, y = df.drop(columns="label"), df["label"]
print(f"{len(df)} rows | benign {sum(y == 0)} | phishing {sum(y == 1)}")

Xtr, Xte, ytr, yte = train_test_split(
    X, y, test_size=0.25, stratify=y, random_state=42)

# ---------------------------------------------------------------- train
model = lgb.LGBMClassifier(
    n_estimators=400,
    learning_rate=0.05,
    num_leaves=31,
    class_weight="balanced",
    importance_type="gain",      # gain, not split count
    random_state=42,
    verbose=-1,
)
model.fit(Xtr, ytr)

prob = model.predict_proba(Xte)[:, 1]
pred = (prob >= THRESHOLD).astype(int)

# ---------------------------------------------------------------- metrics
print(f"\n--- at threshold {THRESHOLD} ---")
print(f"accuracy  {accuracy_score(yte, pred):.3f}")
print(f"precision {precision_score(yte, pred):.3f}")
print(f"recall    {recall_score(yte, pred):.3f}")
print(f"auc       {roc_auc_score(yte, prob):.3f}")

tn, fp, fn, tp = confusion_matrix(yte, pred).ravel()
print(f"\nfalse positives (benign flagged): {fp} / {tn + fp}"
      f"  ({100 * fp / (tn + fp):.1f}%)  <- Criterion 1")
print(f"false negatives (missed scams):   {fn} / {fn + tp}"
      f"  ({100 * fn / (fn + tp):.1f}%)")

# ---------------------------------------------------------------- threshold sweep
print("\nthreshold  precision  recall   FPs")
for t in [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]:
    pt = (prob >= t).astype(int)
    f = ((pt == 1) & (yte == 0)).sum()
    print(f"   {t:.1f}       {precision_score(yte, pt, zero_division=0):.3f}"
          f"      {recall_score(yte, pt):.3f}   {f:>3}")

# ---------------------------------------------------------------- importance
imp = (pd.Series(model.feature_importances_, index=X.columns)
         .sort_values(ascending=False))
print("\nfeature importance (gain):")
print((imp / imp.sum() * 100).round(1).to_string())

# ---------------------------------------------------------------- shap
explainer = shap.TreeExplainer(model)
sv = explainer.shap_values(Xte)
vals = sv[1] if isinstance(sv, list) else sv          # binary clf shape differs by version

mean_abs = pd.Series(np.abs(vals).mean(axis=0), index=X.columns) \
             .sort_values(ascending=False)
print("\nSHAP mean |impact|:")
print(mean_abs.round(4).to_string())


def reasons_for(feature_row, top_n=4):
    """Per-prediction reasons -> Criterion 3. Import this in the API."""
    arr = feature_row[X.columns].to_frame().T if hasattr(feature_row, "to_frame") \
          else pd.DataFrame([feature_row])[X.columns]
    s = explainer.shap_values(arr)
    v = (s[1] if isinstance(s, list) else s)[0]
    pairs = sorted(zip(X.columns, v), key=lambda kv: -abs(kv[1]))[:top_n]
    return [
        {"code": name,
         "weight": round(float(w) * 100, 1),
         "value": float(arr.iloc[0][name])}
        for name, w in pairs
    ]


print("\n--- example explanations ---")
for i in [0, 1, 2]:
    tag = "PHISH" if yte.iloc[i] == 1 else "benign"
    print(f"\nrow {i} ({tag}) scored {prob[i]:.2f}")
    for r in reasons_for(Xte.iloc[i]):
        print(f"   {r['code']:15} {r['weight']:+7.1f}   value={r['value']}")

# ---------------------------------------------------------------- save
joblib.dump(
    {"model": model, "features": list(X.columns), "threshold": THRESHOLD},
    "data/model.pkl")
print("\nsaved -> data/model.pkl")