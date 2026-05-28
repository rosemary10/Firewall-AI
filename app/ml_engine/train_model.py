import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score
import joblib


# Load dataset
dataset = pd.read_csv("../../datasets/network_traffic.csv")


# Convert labels into numbers
dataset["label"] = dataset["label"].map({
    "normal": 0,
    "suspicious": 1
})


# Features
X = dataset[[
    "packet_length",
    "protocol",
    "destination_port"
]]


# Labels
y = dataset["label"]


# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)


# Create AI model
model = DecisionTreeClassifier()


# Train model
model.fit(X_train, y_train)


# Predictions
predictions = model.predict(X_test)


# Accuracy
accuracy = accuracy_score(y_test, predictions)

print(f"\nModel Accuracy: {accuracy * 100:.2f}%")

# Save model
joblib.dump(model, "../../models/firewall_model.pkl")

print("Model saved successfully!")