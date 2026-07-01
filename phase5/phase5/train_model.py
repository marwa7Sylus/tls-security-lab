#!/usr/bin/env python3
"""
train_model.py - Trains and saves an SSL/TLS security model

This script:
1. Loads SSL/TLS configuration data from CSV
2. Trains a Random Forest model
3. Saves the trained model to 'ssl_security_model.pkl'
"""

import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Load and prepare the data
print("Loading training data...")
data = pd.read_csv("datav2.csv")

# Convert text Yes/No to boolean
for col in data.columns:
    if col != 'website' and col != 'cert_expiry_days' and col != 'cert_bits':
        data[col] = data[col].map({'Yes': True, 'No': False})

# Define features for training
features = [
    'sslv2_supported', 'sslv3_supported', 'tlsv1_0_supported', 
    'tlsv1_1_supported', 'tlsv1_2_supported', 'tlsv1_3_supported',
    'heartbleed_vulnerable', 'poodle_vulnerable', 'secure_renegotiation',
    'weak_ciphers', 'rc4_ciphers', 'des_ciphers', 'cert_expiry_days', 'cert_bits'
]

# Prepare training data
X = data[features]
y = data['is_secure']

# Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

# Train the Random Forest model
print("Training model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"Model accuracy: {accuracy:.2f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Show feature importance
importances = model.feature_importances_
feature_importance = sorted(zip(features, importances), key=lambda x: x[1], reverse=True)
print("\nFeature Importance:")
for feature, importance in feature_importance:
    print(f"- {feature}: {importance:.4f}")

# Save the model
model_file = 'ssl_security_model.pkl'
with open(model_file, 'wb') as f:
    pickle.dump(model, f)
with open('model_features.pkl', 'wb') as f:
    pickle.dump(features, f)

print(f"\nModel saved to {model_file}")
print("Done!")
