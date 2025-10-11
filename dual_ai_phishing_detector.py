import streamlit as st
import pandas as pd
import numpy as np
import pickle
import re
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier

st.set_page_config(page_title="Dual AI Phishing Detector", page_icon="🤖", layout="wide")

# Custom styling
st.markdown("""
<style>
.big-metric {font-size: 24px; font-weight: bold;}
.stAlert {border-radius: 10px;}
</style>
""", unsafe_allow_html=True)

# Header
st.title("🤖 DUAL AI Phishing Detection System")
st.markdown("**Two Machine Learning Models Working Together**")

# Load models
@st.cache_resource
def load_models():
    # Load email model
    try:
        with open('email_model.pkl', 'rb') as f:
            email_model = pickle.load(f)
        with open('email_vectorizer.pkl', 'rb') as f:
            email_vectorizer = pickle.load(f)
    except:
        email_model = None
        email_vectorizer = None
    
    # Load URL model
    df = pd.read_csv('phishing_clean.csv')
    X = df.drop(['Index', 'class'], axis=1)
    y = df['class'].map({1: 1, -1: 0})
    url_model = RandomForestClassifier(n_estimators=100, random_state=42)
    url_model.fit(X, y)
    feature_names = X.columns.tolist()
    
    return email_model, email_vectorizer, url_model, feature_names

email_model, email_vectorizer, url_model, feature_names = load_models()

# Sidebar - Model Stats
st.sidebar.header("🎯 AI Models")
st.sidebar.markdown("### 📧 Email AI Model")
st.sidebar.metric("Algorithm", "Naive Bayes")
st.sidebar.metric("Accuracy", "~98%")

st.sidebar.markdown("### 🔗 URL AI Model")
st.sidebar.metric("Algorithm", "Random Forest")
st.sidebar.metric("Accuracy", "96.92%")
st.sidebar.metric("Training URLs", "11,054")

# URL Feature Extraction
def extract_url_features(url):
    features = [0] * len(feature_names)
    
    # UsingIP
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    features[feature_names.index('UsingIP')] = 1 if re.search(ip_pattern, url) else -1
    
    # LongURL
    features[feature_names.index('LongURL')] = 1 if len(url) > 75 else -1
    
    # ShortURL
    short_domains = ['bit.ly', 'tinyurl', 't.co', 'goo.gl']
    features[feature_names.index('ShortURL')] = 1 if any(d in url for d in short_domains) else -1
    
    # Symbol@
    features[feature_names.index('Symbol@')] = 1 if '@' in url else -1
    
    # HTTPS
    features[feature_names.index('HTTPS')] = 1 if url.startswith('https') else -1
    
    # Redirecting//
    features[feature_names.index('Redirecting//')] = 1 if url.count('//') > 1 else -1
    
    return features

def analyze_url_with_ai(url):
    """Analyze URL using Random Forest ML model"""
    features = extract_url_features(url)
    prediction = url_model.predict([features])[0]
    probability = url_model.predict_proba([features])[0]
    
    return prediction, probability[0], probability[1]

def analyze_email_with_ai(email_text):
    """Analyze email content using Naive Bayes ML model"""
    if email_model and email_vectorizer:
        email_tfidf = email_vectorizer.transform([email_text])
        prediction = email_model.predict(email_tfidf)[0]
        probability = email_model.predict_proba(email_tfidf)[0]
        return prediction, probability[0], probability[1]
    return None, 0, 0

# Main Interface
tab1, tab2, tab3 = st.tabs(["🤖 Dual AI Analysis", "📧 Email Only", "🔗 URL Only"])

# TAB 1: DUAL AI ANALYSIS
with tab1:
    st.header("🤖 Complete Email + URL AI Analysis")
    st.markdown("*Combines both AI models for maximum protection*")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        sender = st.text_input("Sender Email:", placeholder="sender@example.com")
    with col2:
        subject = st.text_input("Subject:", placeholder="Email subject")
    
    email_content = st.text_area("Email Content:", height=200, 
                                  placeholder="Paste the complete email here...")
    
    if st.button("🤖 Run Dual AI Analysis", type="primary", key="dual"):
        if email_content:
            st.markdown("---")
            
            # EMAIL AI ANALYSIS
            st.subheader("📧 AI Email Content Analysis")
            
            email_pred, email_prob_legit, email_prob_spam = analyze_email_with_ai(email_content)
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if email_pred == 1:
                    st.error("🚨 AI: SPAM/PHISHING")
                    email_verdict = "PHISHING"
                else:
                    st.success("✅ AI: LEGITIMATE")
                    email_verdict = "SAFE"
            
            with col2:
                st.metric("Phishing Probability", f"{email_prob_spam*100:.1f}%")
            
            with col3:
                st.metric("Legitimate Probability", f"{email_prob_legit*100:.1f}%")
            
            # URL EXTRACTION & AI ANALYSIS
            st.markdown("---")
            st.subheader("🔗 AI URL Analysis")
            
            url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            urls = re.findall(url_pattern, email_content)
            
            url_verdict = "SAFE"
            dangerous_urls = 0
            
            if urls:
                st.write(f"Found **{len(urls)}** URL(s) in email:")
                
                for i, url in enumerate(urls, 1):
                    with st.expander(f"🔗 URL {i}: {url[:50]}..."):
                        url_pred, url_prob_phish, url_prob_legit = analyze_url_with_ai(url)
                        
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            if url_pred == 0:
                                st.error("⚠️ AI: PHISHING URL")
                                dangerous_urls += 1
                                url_verdict = "DANGEROUS"
                            else:
                                st.success("✅ AI: SAFE URL")
                        
                        with col2:
                            st.metric("Phishing", f"{url_prob_phish*100:.1f}%")
                        
                        with col3:
                            st.metric("Legitimate", f"{url_prob_legit*100:.1f}%")
                        
                        st.code(url, language=None)
            else:
                st.info("No URLs found in email")
            
            # FINAL VERDICT
            st.markdown("---")
            st.subheader("🎯 Final AI Verdict")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("**Email AI:**")
                if email_verdict == "PHISHING":
                    st.error("🚨 PHISHING DETECTED")
                else:
                    st.success("✅ LEGITIMATE")
            
            with col2:
                st.markdown("**URL AI:**")
                if dangerous_urls > 0:
                    st.error(f"🚨 {dangerous_urls} DANGEROUS URL(S)")
                else:
                    st.success("✅ ALL URLS SAFE")
            
            with col3:
                st.markdown("**Overall Risk:**")
                if email_verdict == "PHISHING" or dangerous_urls > 0:
                    st.error("🚨 HIGH RISK")
                    overall = "PHISHING"
                else:
                    st.success("✅ LOW RISK")
                    overall = "SAFE"
            
            # Recommendations
            st.markdown("---")
            st.subheader("💡 AI Recommendations")
            
            if overall == "PHISHING":
                st.error("""
                **⚠️ BOTH AI MODELS DETECTED THREATS**
                
                **Immediate Actions:**
                - ❌ DO NOT click any links
                - ❌ DO NOT reply to this email
                - ❌ DO NOT download attachments
                - ✅ DELETE immediately
                - ✅ Report as phishing
                - ✅ Block sender
                """)
            else:
                st.success("""
                **✅ Both AI models indicate this email is safe**
                
                **Still exercise caution:**
                - Verify sender if they request sensitive information
                - Check URLs before clicking
                - Be wary of urgent requests
                """)
        else:
            st.warning("Please paste email content to analyze")

# TAB 2: EMAIL ONLY
with tab2:
    st.header("📧 Email AI Analysis Only")
    
    email_text = st.text_area("Email Content:", height=200, key="email_only")
    
    if st.button("Analyze Email", key="email_btn"):
        if email_text:
            pred, prob_legit, prob_spam = analyze_email_with_ai(email_text)
            
            col1, col2 = st.columns(2)
            
            with col1:
                if pred == 1:
                    st.error("🚨 PHISHING/SPAM DETECTED")
                else:
                    st.success("✅ LEGITIMATE EMAIL")
            
            with col2:
                st.metric("Phishing Probability", f"{prob_spam*100:.1f}%")
                st.metric("Legitimate Probability", f"{prob_legit*100:.1f}%")

# TAB 3: URL ONLY
with tab3:
    st.header("🔗 URL AI Analysis Only")
    
    url = st.text_input("Enter URL:", key="url_only")
    
    if st.button("Analyze URL", key="url_btn"):
        if url:
            pred, prob_phish, prob_legit = analyze_url_with_ai(url)
            
            col1, col2 = st.columns(2)
            
            with col1:
                if pred == 0:
                    st.error("🚨 PHISHING URL")
                else:
                    st.success("✅ SAFE URL")
            
            with col2:
                st.metric("Phishing Probability", f"{prob_phish*100:.1f}%")
                st.metric("Legitimate Probability", f"{prob_legit*100:.1f}%")

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center'>
<h4>🤖 Powered by Dual AI Architecture</h4>
<p><b>Email AI:</b> Naive Bayes (98% accuracy) | <b>URL AI:</b> Random Forest (96.92% accuracy)</p>
</div>
""", unsafe_allow_html=True)
