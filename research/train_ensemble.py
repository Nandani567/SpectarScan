
# import os
# import pandas as pd
# import joblib

# from sklearn.model_selection import train_test_split
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.metrics import classification_report, confusion_matrix
# from xgboost import XGBClassifier

# os.makedirs("data/processed", exist_ok=True)
# os.makedirs("models", exist_ok=True)

# df = pd.read_csv("data/raw/phishing_dataset.csv")

# print("Original shape:", df.shape)
# print("Duplicate rows:", df.duplicated().sum())

# df = df.drop_duplicates().reset_index(drop=True)

# print("New shape:", df.shape)
# print("Duplicate rows after cleaning:", df.duplicated().sum())


# df["Result"] = df["Result"].map({-1: 0, 1: 1})

# print("Class distribution:")
# print(df["Result"].value_counts(normalize=True))

# df.to_csv("data/processed/phishing_cleaned.csv", index=False)


# X = df.drop("Result", axis=1)
# y = df["Result"]

# X_train, X_test, y_train, y_test = train_test_split(
#     X,
#     y,
#     test_size=0.2,
#     random_state=42
# )

# print("Training set shape:", X_train.shape, y_train.shape)
# print("Testing set shape:", X_test.shape, y_test.shape)

# # Save splits
# X_train.to_csv("data/processed/X_train.csv", index=False)
# X_test.to_csv("data/processed/X_test.csv", index=False)
# y_train.to_csv("data/processed/y_train.csv", index=False)
# y_test.to_csv("data/processed/y_test.csv", index=False)



# rf = RandomForestClassifier(
#     n_estimators=100,
#     random_state=42
# )

# rf.fit(X_train, y_train)

# y_pred_rf = rf.predict(X_test)

# print("\n===== Random Forest Results =====")
# print(confusion_matrix(y_test, y_pred_rf))
# print(classification_report(y_test, y_pred_rf))




# xgb = XGBClassifier(
#     n_estimators=200,
#     max_depth=6,
#     learning_rate=0.1,
#     eval_metric="logloss",
#     random_state=42
# )

# xgb.fit(X_train, y_train)

# y_pred_xgb = xgb.predict(X_test)

# print("\n===== XGBoost Results =====")
# print(confusion_matrix(y_test, y_pred_xgb))
# print(classification_report(y_test, y_pred_xgb))



# joblib.dump(rf, "models/phishing_random_forest.joblib")
# joblib.dump(xgb, "models/phishing_xgboost.joblib")

# print("\nModels saved successfully.")




import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from xgboost import XGBClassifier

os.makedirs("data/processed", exist_ok=True)
os.makedirs("models", exist_ok=True)

df = pd.read_csv("data/raw/phishing_dataset.csv")

print("Original shape:", df.shape)
print("Duplicate rows:", df.duplicated().sum())

df = df.drop_duplicates().reset_index(drop=True)

print("New shape:", df.shape)
print("Duplicate rows after cleaning:", df.duplicated().sum())

# Convert labels
df["Result"] = df["Result"].map({-1: 0, 1: 1})

print("Class distribution:")
print(df["Result"].value_counts(normalize=True))

df.to_csv("data/processed/phishing_cleaned.csv", index=False)

X = df.drop("Result", axis=1)
y = df["Result"]

# IMPORTANT: stratify for balanced phishing detection
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training set shape:", X_train.shape)
print("Testing set shape:", X_test.shape)

# Save feature names for API
feature_names = X.columns.tolist()
joblib.dump(feature_names, "models/feature_names.joblib")

# Save splits
X_train.to_csv("data/processed/X_train.csv", index=False)
X_test.to_csv("data/processed/X_test.csv", index=False)
y_train.to_csv("data/processed/y_train.csv", index=False)
y_test.to_csv("data/processed/y_test.csv", index=False)

# Random Forest
rf = RandomForestClassifier(
    n_estimators=150,
    random_state=42,
    n_jobs=-1
)

rf.fit(X_train, y_train)

y_pred_rf = rf.predict(X_test)

print("\n===== Random Forest Results =====")
print(confusion_matrix(y_test, y_pred_rf))
print(classification_report(y_test, y_pred_rf))

# XGBoost (safe configuration)
xgb = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    eval_metric="logloss",
    use_label_encoder=False,
    random_state=42
)

xgb.fit(X_train, y_train)

y_pred_xgb = xgb.predict(X_test)

print("\n===== XGBoost Results =====")
print(confusion_matrix(y_test, y_pred_xgb))
print(classification_report(y_test, y_pred_xgb))

# Save models
joblib.dump(rf, "models/phishing_random_forest.joblib")
joblib.dump(xgb, "models/phishing_xgboost.joblib")

print("\nModels saved successfully.")