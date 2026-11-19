#!/usr/bin/env python3
"""
train_model.py — train RandomForest on the 18-column clean ARP dataset.

INPUT SCHEMA (dataset/arp_dataset_clean.csv, 18 columns):
    timestamp            — row identifier (ignored)
    arp_rate             ← model feature 1
    request_reply_imbalance  ← 2
    src_ip_entropy       ← 3
    unique_src_ip_count  ← 4
    src_mac_entropy      ← 5
    target_ip_entropy    ← 6
    unique_target_ip_count   ← 7
    broadcast_fraction   ← 8
    gratuitous_fraction  ← 9
    self_mac_mismatch_count ← 10
    delta_arp_rate       ← 11
    new_ip_ratio         ← 12
    cross_switch_spread  ← 13
    top_port_share       ← 14
    unique_host_ports    ← 15
    top_src_ip_share     — diagnostic (ignored)
    label                — target (0 = normal, 1 = attack)

OUTPUT:
    models/arp_rf.pkl
    report/report.txt
    report/metrics.json
    report/roc_curve.png
    report/pr_curve.png
    report/confusion_matrix.png
    report/feature_importance.png

USAGE:
    python3 training/train_model.py dataset/arp_dataset_clean.csv models/arp_rf.pkl
"""
import os, sys, time, json
from datetime import datetime

# NOTE: If you see many "NumPy 1.x cannot be run in NumPy 2.x" warnings,
# they are caused by system-level numexpr/bottleneck that pandas tries to
# import as optional accelerators. They do NOT affect training metrics.
# Fix with:
#     sudo apt remove -y python3-numexpr python3-bottleneck

try:
    import numpy as np
    import pandas as pd
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import (
        train_test_split, StratifiedKFold, cross_validate,
    )
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        roc_auc_score, roc_curve, precision_recall_curve, auc,
        confusion_matrix, classification_report,
    )
except ImportError as e:
    sys.exit(f"missing dependency: {e}\n"
             f"install with: sudo apt install -y python3-sklearn "
             f"python3-pandas python3-matplotlib python3-joblib")

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_PLOTS = True
except ImportError:
    HAS_PLOTS = False
    print("[WARN] matplotlib not installed — skipping plots")

# ── Config ─────────────────────────────────────────────────────────────
# MUST match controller/controller.py FEATURE_COLUMNS EXACTLY (same order).
FEATURE_COLUMNS = [
    "arp_rate",
    "request_reply_imbalance",
    "src_ip_entropy",
    "unique_src_ip_count",
    "src_mac_entropy",
    "target_ip_entropy",
    "unique_target_ip_count",
    "broadcast_fraction",
    "gratuitous_fraction",
    "self_mac_mismatch_count",
    "delta_arp_rate",
    "new_ip_ratio",
    "cross_switch_spread",
    "top_port_share",
    "unique_host_ports",
]
assert len(FEATURE_COLUMNS) == 15, "FEATURE_COLUMNS must be exactly 15"

# Columns the clean CSV contains but the model does NOT use:
#   timestamp         — row identifier
#   top_src_ip_share  — diagnostic
#   label             — target (handled separately)

DATASET    = sys.argv[1] if len(sys.argv) > 1 else "dataset/arp_dataset_clean.csv"
MODEL_OUT  = sys.argv[2] if len(sys.argv) > 2 else "models/arp_rf.pkl"
REPORT_DIR = "report"
RANDOM_STATE = 42
TEST_SIZE    = 0.25
CV_FOLDS     = 5

os.makedirs(os.path.dirname(MODEL_OUT) or ".", exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

# ── Load ───────────────────────────────────────────────────────────────
print(f"Loading {DATASET} ...")
if not os.path.exists(DATASET):
    sys.exit(f"dataset file not found: {DATASET}")

df = pd.read_csv(DATASET)
print(f"  {len(df)} rows, {len(df.columns)} columns")
print(f"  CSV columns present: {list(df.columns)}")

# ── Schema verification ───────────────────────────────────────────────
missing_features = [c for c in FEATURE_COLUMNS if c not in df.columns]
missing_label    = "label" not in df.columns

if missing_features:
    sys.exit(f"\n❌ Missing required feature columns in CSV:\n"
             f"   {missing_features}\n\n"
             f"   Expected 15 features (must match controller/controller.py):\n"
             f"   {FEATURE_COLUMNS}\n\n"
             f"   CSV actually has:\n   {list(df.columns)}")

if missing_label:
    sys.exit("❌ 'label' column missing from CSV")

# Extra columns are fine — we explicitly ignore them.
extra = [c for c in df.columns if c not in FEATURE_COLUMNS and c != "label"]
if extra:
    print(f"\n  ℹ️  Extra columns present (will be ignored by the model):")
    for c in extra:
        print(f"       {c}")
    print(f"     These are {'timestamp' if 'timestamp' in extra else ''}"
          f"{' and ' if 'timestamp' in extra and 'top_src_ip_share' in extra else ''}"
          f"{'top_src_ip_share' if 'top_src_ip_share' in extra else ''}"
          f" — not model inputs.")

print(f"\n  Model features ({len(FEATURE_COLUMNS)}):")
for i, c in enumerate(FEATURE_COLUMNS, 1):
    print(f"    {i:2d}. {c}")

# ── Extract X, y ──────────────────────────────────────────────────────
X = df[FEATURE_COLUMNS].astype(float).fillna(0.0).values
y = df["label"].astype(int).values

if len(np.unique(y)) < 2:
    sys.exit(f"❌ Only one class present in labels: {np.unique(y)}")

print(f"\n  Class distribution:")
for cls, cnt in zip(*np.unique(y, return_counts=True)):
    print(f"    label={cls}  : {cnt:6d}  ({100*cnt/len(y):.1f}%)")

# ── Train/test split ──────────────────────────────────────────────────
X_tr, X_te, y_tr, y_te = train_test_split(
    X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y,
)
print(f"\n  Train: {len(X_tr)}   Test: {len(X_te)}")

# ── Train ─────────────────────────────────────────────────────────────
print("\nTraining RandomForest (200 trees, class_weight=balanced) ...")
clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    min_samples_split=5,
    min_samples_leaf=2,
    class_weight="balanced",
    n_jobs=-1,
    random_state=RANDOM_STATE,
)
t0 = time.time()
clf.fit(X_tr, y_tr)
train_time = time.time() - t0
print(f"  trained in {train_time:.2f} s")

# ── Inference timing ──────────────────────────────────────────────────
N_BENCH = 200
_ = clf.predict_proba(X_te[:1])  # warm-up
t0 = time.perf_counter()
for _ in range(N_BENCH):
    _ = clf.predict_proba(X_te[:1])
single_us = (time.perf_counter() - t0) / N_BENCH * 1e6

t0 = time.perf_counter()
_ = clf.predict_proba(X_te[:1000])
batch_us = (time.perf_counter() - t0) * 1e6 / 1000

print(f"  latency: {single_us:.1f} µs / prediction  "
      f"(batched: {batch_us:.1f} µs / sample)")

# ── Predictions ───────────────────────────────────────────────────────
y_pred  = clf.predict(X_te)
y_proba = clf.predict_proba(X_te)[:, 1]

# ── Metrics ───────────────────────────────────────────────────────────
acc      = accuracy_score(y_te, y_pred)
prec_mac = precision_score(y_te, y_pred, average="macro", zero_division=0)
rec_mac  = recall_score(y_te, y_pred, average="macro", zero_division=0)
f1_mac   = f1_score(y_te, y_pred, average="macro", zero_division=0)
auc_roc  = roc_auc_score(y_te, y_proba)

prec_neg = precision_score(y_te, y_pred, pos_label=0, zero_division=0)
rec_neg  = recall_score(y_te, y_pred, pos_label=0, zero_division=0)
f1_neg   = f1_score(y_te, y_pred, pos_label=0, zero_division=0)
prec_pos = precision_score(y_te, y_pred, pos_label=1, zero_division=0)
rec_pos  = recall_score(y_te, y_pred, pos_label=1, zero_division=0)
f1_pos   = f1_score(y_te, y_pred, pos_label=1, zero_division=0)

cm = confusion_matrix(y_te, y_pred)
tn, fp, fn, tp = cm.ravel()
fpr_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
fnr_rate = fn / (fn + tp) if (fn + tp) > 0 else 0.0

# ── 5-fold CV ─────────────────────────────────────────────────────────
print("\nRunning 5-fold cross-validation ...")
cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True,
                     random_state=RANDOM_STATE)
cvr = cross_validate(
    clf, X, y, cv=cv,
    scoring=["accuracy", "precision_macro", "recall_macro",
             "f1_macro", "roc_auc"],
    n_jobs=-1,
)
cv_acc    = cvr["test_accuracy"].mean();         cv_acc_s    = cvr["test_accuracy"].std()
cv_prec   = cvr["test_precision_macro"].mean();  cv_prec_s   = cvr["test_precision_macro"].std()
cv_rec    = cvr["test_recall_macro"].mean();     cv_rec_s    = cvr["test_recall_macro"].std()
cv_f1     = cvr["test_f1_macro"].mean();         cv_f1_s     = cvr["test_f1_macro"].std()
cv_auc    = cvr["test_roc_auc"].mean();          cv_auc_s    = cvr["test_roc_auc"].std()
print(f"  accuracy : {cv_acc:.4f} ± {cv_acc_s:.4f}")
print(f"  precision: {cv_prec:.4f} ± {cv_prec_s:.4f}")
print(f"  recall   : {cv_rec:.4f} ± {cv_rec_s:.4f}")
print(f"  f1       : {cv_f1:.4f} ± {cv_f1_s:.4f}")
print(f"  auc      : {cv_auc:.4f} ± {cv_auc_s:.4f}")

# ── Feature importance ────────────────────────────────────────────────
feat_imp = sorted(
    zip(FEATURE_COLUMNS, clf.feature_importances_),
    key=lambda x: -x[1],
)

# ── Plots ─────────────────────────────────────────────────────────────
pr_auc = None
if HAS_PLOTS:
    fpr, tpr, _ = roc_curve(y_te, y_proba)
    plt.figure(figsize=(7, 6))
    plt.plot(fpr, tpr, "b-", lw=2, label=f"AUC = {auc_roc:.4f}")
    plt.plot([0, 1], [0, 1], "k--", alpha=0.4, label="Random")
    plt.xlabel("False Positive Rate"); plt.ylabel("True Positive Rate")
    plt.title("ROC Curve — ARP Flood Detection")
    plt.legend(loc="lower right"); plt.grid(alpha=0.3); plt.tight_layout()
    plt.savefig(os.path.join(REPORT_DIR, "roc_curve.png"), dpi=150)
    plt.close()

    pr_arr, rc_arr, _ = precision_recall_curve(y_te, y_proba)
    pr_auc = auc(rc_arr, pr_arr)
    plt.figure(figsize=(7, 6))
    plt.plot(rc_arr, pr_arr, "g-", lw=2, label=f"AUC = {pr_auc:.4f}")
    plt.xlabel("Recall"); plt.ylabel("Precision")
    plt.title("Precision-Recall Curve — ARP Flood Detection")
    plt.legend(loc="lower left"); plt.grid(alpha=0.3); plt.tight_layout()
    plt.savefig(os.path.join(REPORT_DIR, "pr_curve.png"), dpi=150)
    plt.close()

    fig, ax = plt.subplots(figsize=(6, 5))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["normal", "attack"])
    ax.set_yticklabels(["normal", "attack"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
    ax.set_title("Confusion Matrix")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                    color="white" if cm[i, j] > cm.max()/2 else "black",
                    fontsize=16, fontweight="bold")
    plt.colorbar(im); plt.tight_layout()
    plt.savefig(os.path.join(REPORT_DIR, "confusion_matrix.png"), dpi=150)
    plt.close()

    plt.figure(figsize=(9, 6))
    names, vals = zip(*feat_imp)
    plt.barh(range(len(names)), vals, color="steelblue")
    plt.yticks(range(len(names)), names)
    plt.xlabel("Importance"); plt.title("Feature Importance")
    plt.gca().invert_yaxis(); plt.tight_layout()
    plt.savefig(os.path.join(REPORT_DIR, "feature_importance.png"), dpi=150)
    plt.close()

    print(f"\n  Plots written to {REPORT_DIR}/")

# ── Save model ────────────────────────────────────────────────────────
joblib.dump(clf, MODEL_OUT)
print(f"  Model saved: {MODEL_OUT}")

# ── metrics.json ──────────────────────────────────────────────────────
metrics = {
    "dataset": DATASET,
    "trained_at": datetime.now().isoformat(timespec="seconds"),
    "input_schema": {
        "csv_columns": list(df.columns),
        "model_features": FEATURE_COLUMNS,
        "ignored_columns": [c for c in df.columns
                            if c not in FEATURE_COLUMNS and c != "label"],
        "target_column": "label",
    },
    "n_rows": len(df),
    "n_features": len(FEATURE_COLUMNS),
    "class_balance": {
        "normal": int((y == 0).sum()),
        "attack": int((y == 1).sum()),
    },
    "train_size": len(X_tr),
    "test_size": len(X_te),
    "train_time_s": round(train_time, 3),
    "single_predict_latency_us": round(single_us, 2),
    "batched_predict_latency_us": round(batch_us, 2),
    "test_metrics": {
        "accuracy":         round(float(acc), 4),
        "precision_macro":  round(float(prec_mac), 4),
        "recall_macro":     round(float(rec_mac), 4),
        "f1_macro":         round(float(f1_mac), 4),
        "auc_roc":          round(float(auc_roc), 4),
        "auc_pr":           round(float(pr_auc), 4) if pr_auc else None,
        "precision_normal": round(float(prec_neg), 4),
        "recall_normal":    round(float(rec_neg), 4),
        "f1_normal":        round(float(f1_neg), 4),
        "precision_attack": round(float(prec_pos), 4),
        "recall_attack":    round(float(rec_pos), 4),
        "f1_attack":        round(float(f1_pos), 4),
        "false_positive_rate": round(float(fpr_rate), 4),
        "false_negative_rate": round(float(fnr_rate), 4),
    },
    "confusion_matrix": {"tn": int(tn), "fp": int(fp),
                          "fn": int(fn), "tp": int(tp)},
    "cv_5fold": {
        "accuracy_mean":  round(float(cv_acc), 4),
        "accuracy_std":   round(float(cv_acc_s), 4),
        "precision_mean": round(float(cv_prec), 4),
        "precision_std":  round(float(cv_prec_s), 4),
        "recall_mean":    round(float(cv_rec), 4),
        "recall_std":     round(float(cv_rec_s), 4),
        "f1_mean":        round(float(cv_f1), 4),
        "f1_std":         round(float(cv_f1_s), 4),
        "auc_mean":       round(float(cv_auc), 4),
        "auc_std":        round(float(cv_auc_s), 4),
    },
    "feature_importances": {n: round(float(v), 4) for n, v in feat_imp},
}
with open(os.path.join(REPORT_DIR, "metrics.json"), "w") as f:
    json.dump(metrics, f, indent=2)

# ── report.txt ────────────────────────────────────────────────────────
report_path = os.path.join(REPORT_DIR, "report.txt")
with open(report_path, "w") as f:
    def w(line=""):
        f.write(line + "\n")

    w("=" * 78)
    w("  ARP FLOOD DETECTION — MODEL TRAINING REPORT")
    w("=" * 78)
    w()
    w(f"  Generated:      {metrics['trained_at']}")
    w(f"  Dataset:        {DATASET}")
    w(f"  Rows:           {metrics['n_rows']}")
    w(f"  Model features: {len(FEATURE_COLUMNS)}")
    w(f"  Train / Test:   {len(X_tr)} / {len(X_te)}")
    w(f"  Model:          RandomForestClassifier (200 trees)")
    w(f"  Class weight:   balanced")
    w()
    w("  Class distribution:")
    w(f"    normal (0):   {metrics['class_balance']['normal']:6d}")
    w(f"    attack (1):   {metrics['class_balance']['attack']:6d}")
    w()
    w("  Input schema:")
    w(f"    CSV has {len(df.columns)} columns. Model uses 15 features:")
    for i, c in enumerate(FEATURE_COLUMNS, 1):
        w(f"      {i:2d}. {c}")
    w()
    w(f"    Ignored CSV columns: {metrics['input_schema']['ignored_columns']}")
    w()
    w("-" * 78)
    w("  1. TRAINING PERFORMANCE")
    w("-" * 78)
    w()
    w(f"  Train time:               {train_time:.2f} s")
    w(f"  Inference (single):       {single_us:.1f} µs per window")
    w(f"  Inference (batched 1000): {batch_us:.1f} µs per window")
    w()
    w("  5-fold cross-validation (mean ± std):")
    w(f"    Accuracy:  {cv_acc:.4f}  ± {cv_acc_s:.4f}")
    w(f"    Precision: {cv_prec:.4f}  ± {cv_prec_s:.4f}")
    w(f"    Recall:    {cv_rec:.4f}  ± {cv_rec_s:.4f}")
    w(f"    F1:        {cv_f1:.4f}  ± {cv_f1_s:.4f}")
    w(f"    AUC-ROC:   {cv_auc:.4f}  ± {cv_auc_s:.4f}")
    w()
    w("-" * 78)
    w("  2. TEST-SET METRICS")
    w("-" * 78)
    w()
    w(f"  Accuracy:       {acc:.4f}")
    w(f"  F1 (macro):     {f1_mac:.4f}")
    w(f"  AUC-ROC:        {auc_roc:.4f}")
    if pr_auc:
        w(f"  AUC-PR:         {pr_auc:.4f}")
    w()
    w("  Per-class:")
    w(f"    {'class':10s} {'precision':>10s} {'recall':>10s} {'f1':>10s}")
    w(f"    {'-'*10} {'-'*10} {'-'*10} {'-'*10}")
    w(f"    {'normal':10s} {prec_neg:10.4f} {rec_neg:10.4f} {f1_neg:10.4f}")
    w(f"    {'attack':10s} {prec_pos:10.4f} {rec_pos:10.4f} {f1_pos:10.4f}")
    w()
    w("  Confusion matrix:")
    w("                       predicted    predicted")
    w("                       normal       attack")
    w(f"    actual normal      {tn:6d}       {fp:6d}")
    w(f"    actual attack      {fn:6d}       {tp:6d}")
    w()
    w(f"  False positive rate:  {fpr_rate:.4f}  ({fp}/{fp+tn} normals misclassified)")
    w(f"  False negative rate:  {fnr_rate:.4f}  ({fn}/{fn+tp} attacks missed)")
    w()
    w("  Runtime implications:")
    if fpr_rate < 0.02:
        w(f"    ✅ FPR {fpr_rate:.2%} — very few false blocks on normal traffic")
    elif fpr_rate < 0.05:
        w(f"    ✅ FPR {fpr_rate:.2%} — acceptable false-block risk")
    else:
        w(f"    ⚠️  FPR {fpr_rate:.2%} — raise --predict-threshold to 0.90 at runtime")
    if fnr_rate < 0.05:
        w(f"    ✅ FNR {fnr_rate:.2%} — very few attacks slip through")
    elif fnr_rate < 0.10:
        w(f"    ✅ FNR {fnr_rate:.2%} — acceptable")
    else:
        w(f"    ⚠️  FNR {fnr_rate:.2%} — some attacks may miss")
    w()
    w("-" * 78)
    w("  3. FEATURE IMPORTANCE")
    w("-" * 78)
    w()
    w(f"  {'feature':32s} {'importance':>12s}")
    w(f"  {'-'*32} {'-'*12}")
    for name, imp in feat_imp:
        bar = "█" * max(1, int(imp * 50)) if imp > 0 else ""
        w(f"  {name:32s} {imp:12.4f}  {bar}")
    w()
    zero_imp = [n for n, v in feat_imp if v == 0.0]
    if zero_imp:
        w(f"  ⚠️  Zero-importance features: {zero_imp}")
        w(f"     These contribute nothing — safe to remove from FEATURE_COLUMNS")
        w(f"     in both controller and train_model for a leaner model.")
    else:
        w(f"  ✅ All features contribute — no zero-importance columns")
    w()
    w("-" * 78)
    w("  4. SKLEARN CLASSIFICATION REPORT")
    w("-" * 78)
    w()
    for line in classification_report(y_te, y_pred,
                                       target_names=["normal", "attack"],
                                       digits=4).splitlines():
        w("  " + line)
    w()
    w("-" * 78)
    w("  5. PLOTS")
    w("-" * 78)
    if HAS_PLOTS:
        w(f"  {REPORT_DIR}/roc_curve.png")
        w(f"  {REPORT_DIR}/pr_curve.png")
        w(f"  {REPORT_DIR}/confusion_matrix.png")
        w(f"  {REPORT_DIR}/feature_importance.png")
    else:
        w("  (matplotlib not installed — no plots generated)")
    w()
    w("-" * 78)
    w("  6. RUNTIME INTEGRATION")
    w("-" * 78)
    w()
    w(f"  Load the model with the controller's --model flag:")
    w()
    w("    sudo python3 controller/controller.py \\")
    w("        --interfaces s1-cpu1 s2-cpu1 s3-cpu1 s4-cpu1 s11-cpu1 \\")
    w("        --label normal --dataset /tmp/live.csv \\")
    w(f"        --model {MODEL_OUT} \\")
    w("        --predict-threshold 0.90 \\")
    w("        --port-share-threshold 0.30 \\")
    w("        --port-pkts-threshold 15 \\")
    w("        --block-hold 15.0")
    w()
    w("  The controller calls predict_proba([features]) once per 1-second")
    w("  window. If prob_attack >= 0.90 AND top_port_share >= 0.30 AND")
    w("  port_pkts_raw >= 15, it installs a tbl_block_port entry on")
    w("  (top_sw_id, top_ingress_port) from the SAME CSV row, held 15 s.")
    w()
    w("=" * 78)

print(f"\n  Report written: {report_path}")

# ── Terminal summary ──────────────────────────────────────────────────
print("\n" + "=" * 78)
print("  FINAL SUMMARY")
print("=" * 78)
print(f"  Accuracy       : {acc:.4f}")
print(f"  F1 (macro)     : {f1_mac:.4f}")
print(f"  AUC-ROC        : {auc_roc:.4f}")
print(f"  FPR / FNR      : {fpr_rate:.4f} / {fnr_rate:.4f}")
print(f"  Inference      : {single_us:.0f} µs / window")
print(f"  Model          : {MODEL_OUT}")
print(f"  Report         : {report_path}")
print("=" * 78)

# ── Recommendations ──────────────────────────────────────────────────
print("\nRuntime recommendations:")
if fpr_rate > 0.05:
    print(f"  ⚠️  FPR {fpr_rate:.2%} > 5% — use --predict-threshold 0.90")
else:
    print(f"  ✅ FPR {fpr_rate:.2%} acceptable — --predict-threshold 0.70 is fine")
if fnr_rate > 0.10:
    print(f"  ⚠️  FNR {fnr_rate:.2%} > 10% — some attacks missed; "
          f"more training data or threshold tuning may help")
