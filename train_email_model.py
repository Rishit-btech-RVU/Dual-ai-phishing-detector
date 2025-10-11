import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import pickle

print("📧 Training Email Phishing Detection Model...")

# Load email dataset
df = pd.read_csv('email_spam.csv', encoding='latin-1')

# Clean the dataset
df = df[['v1', 'v2']]  # Keep only label and text columns
df.columns = ['label', 'text']

# Convert labels to binary (spam=1, ham=0)
df['label'] = df['label'].map({'spam': 1, 'ham': 0})

print(f"✅ Loaded {len(df)} emails")
print(f"Spam: {sum(df['label']==1)}, Legitimate: {sum(df['label']==0)}")

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    df['text'], df['label'], test_size=0.2, random_state=42
)

# Feature extraction with TF-IDF
print("\n🔄 Extracting features with TF-IDF...")
vectorizer = TfidfVectorizer(max_features=3000, stop_words='english')
X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

# Train Naive Bayes model (best for text classification)
print("\n🔄 Training Naive Bayes model...")
nb_model = MultinomialNB()
nb_model.fit(X_train_tfidf, y_train)

# Evaluate
y_pred = nb_model.predict(X_test_tfidf)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n✅ Email Model Accuracy: {accuracy:.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing/Spam']))

# Save the model and vectorizer
print("\n💾 Saving model and vectorizer...")
with open('email_model.pkl', 'wb') as f:
    pickle.dump(nb_model, f)

with open('email_vectorizer.pkl', 'wb') as f:
    pickle.dump(vectorizer, f)

print("✅ Email phishing model trained and saved!")
print(f"📊 Final Accuracy: {accuracy*100:.2f}%")
