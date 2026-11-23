import pandas as pd
import joblib

model=joblib.load("angis_random_forest.pkl")

df=pd.read_csv("Tuesday-ML-training.csv", nrows=10)

X=df.drop(columns=[" Label"])

predictions=model.predict(X)

print("ANGIS AI Threat Predictions")
print("---------------------------")

for i, prediction in enumerate(predictions):
     if prediction == "BENIGN":
        severity = "LOW"
        warning = "No threat detected"
     elif prediction == "FTP-Patator":
          severity = "HIGH"
          warning = "FTP brute-force attack detected"
     else:
         severity = "UNKNOWN"
         warning = "Unknown threat detected"

     print()
     print("Record:",i+1)
     print("Threat:", prediction)
     print("Severity:", severity)
     print("Warning:", warning)
