# Dual AI Phishing Detector

**A dual-AI system combining email and URL machine-learning models for real-time phishing detection.**

---

## 🔍 Project Overview

- **Dual Models**  
  - **Email Classifier**: Naive Bayes on TF-IDF features (trained on 5,574 spam/ham messages, ~98% accuracy).  
  - **URL Classifier**: Random Forest on 11,054 URL features (96.92% accuracy).

- **Key Features**  
  - Real-time analysis of complete email content.  
  - URL extraction and AI-based threat scoring.  
  - Minimalistic, Apple-style Streamlit interface.  
  - Clear risk levels, confidence metrics, and actionable recommendations.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+  
- Git  

### Installation

1. Clone the repo:
git clone https://github.com/Rishit-btech-RVU/dual-ai-phishing-detector.git
cd dual-ai-phishing-detector

2. (Recommended) Create and activate a virtual environment:
python3 -m venv venv
source venv/bin/activate


3. Install dependencies:
pip install -r requirements.txt

### Data Preparation

Place these files in the project root:
- `phishing_clean.csv` (URL dataset)  
- `email_spam.csv` (email dataset)

### Training Models

1. **Train URL model**:Outputs `email_model.pkl` and `email_vectorizer.pkl`.

### Running the App

Launch the Streamlit application:

python3 train_models.py
Outputs `email_model.pkl` and `email_vectorizer.pkl`.

### Running the App

Launch the Streamlit application:
streamlit run dual_ai_phishing_detector.py

Open `http://localhost:8501` in your browser.

---

## 🛠️ Project Structure

dual-ai-phishing-detector/
├── email_spam.csv
├── phishing_clean.csv
├── train_models.py
├── train_email_model.py
├── dual_ai_phishing_detector.py
├── requirements.txt
└── README.md


---

## 📊 Model Performance

- **Email AI** (Naive Bayes): ~98% accuracy  
- **URL AI** (Random Forest): 96.92% accuracy  

---

## 💡 Usage Examples

1. **Full Protection**: Paste complete email to see combined email+URL AI verdict.  
2. **Email Scan**: Analyze only email content for phishing.  
3. **Link Check**: Test individual URLs for phishing probability.

---

## 🤝 Contributing

1. Fork this repository.  
2. Create a feature branch:  
git checkout -b feature-name
3. Commit your changes:  
git commit -m "Add feature"
4. Push to branch:  
git push origin feature-name
5. Open a pull request.

---

  







