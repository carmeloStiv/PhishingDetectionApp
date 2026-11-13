import streamlit as st
import pickle
import numpy as np
import re

# -------------------------------
# Optional: version for quick verification
# -------------------------------
MODEL_VERSION = "v2"

# -------------------------------
# Cleaning function (same as training)
# -------------------------------
def clean_text(text):
    text = str(text).lower()
    # Normalize URLs and emails
    text = re.sub(r'http\S+|www\S+', ' _url_ ', text)
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', ' _email_ ', text)
    text = re.sub(r'\d+', '', text)
    text = re.sub(r'[^a-zA-Z\s_]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

# -------------------------------
# Load model and vectorizer
# -------------------------------
model = pickle.load(open('model.pkl', 'rb'))
vectorizer = pickle.load(open('vectorizer.pkl', 'rb'))

# -------------------------------
# Streamlit config
# -------------------------------
st.set_page_config(page_title="Phishing Detection Tool", layout="centered")
st.title("🔐 AI Phishing Detection Tool")
st.markdown("Detect whether an email or URL is **phishing or legitimate** using NLP.")
st.markdown(f"**Model version:** {MODEL_VERSION}")
st.divider()

# -------------------------------
# Input area
# -------------------------------
text = st.text_area("📩 Enter email or URL:", height=150)

if st.button("Analyse"):
    if text:
        # Clean + transform input
        cleaned = clean_text(text)
        text_vec = vectorizer.transform([cleaned])

        # Prediction probability
        prob = model.predict_proba(text_vec)[0][1]

        # Explainability (top words)
        feature_names = vectorizer.get_feature_names_out()
        coefficients = model.coef_[0]
        indices = text_vec.nonzero()[1]

        word_scores = [(feature_names[i], coefficients[i]) for i in indices]
        word_scores = sorted(word_scores, key=lambda x: abs(x[1]), reverse=True)[:20]

        # -------------------------------
        # Filter out neutral/common tokens (single or multi-word)
        # -------------------------------
        NEUTRAL_TOKENS = ["url", "com", "org", "www", "http", "https", "_email_"]
        word_scores = [
            (w, s) for w, s in word_scores
            if not any(nt in w for nt in NEUTRAL_TOKENS)
        ]

        phishing_indicators = [w for w, s in word_scores if s > 0]

        # -------------------------------
        # Optional whitelist
        # -------------------------------
        SAFE_DOMAINS = ["linkedin.com", "github.com", "python.org"]
        is_whitelisted = any(domain in text.lower() for domain in SAFE_DOMAINS)

        # -------------------------------
        # Determine classification
        # -------------------------------
        if is_whitelisted:
            st.success(f"✅ Legitimate (whitelisted domain)")
        else:
            if prob > 0.85 and len(phishing_indicators) > 0:
                st.error(f"⚠️ Phishing ({prob*100:.2f}%)")
            elif prob > 0.6 and len(phishing_indicators) > 0:
                st.warning(f"⚠️ Suspicious ({prob*100:.2f}%)")
            else:
                st.success(f"✅ Legitimate ({(1-prob)*100:.2f}%)")

        # -------------------------------
        # Display top indicators
        # -------------------------------
        st.subheader("🔍 Key Indicators")
        if word_scores:
            for word, score in word_scores:
                if score > 0:
                    st.write(f"🔴 {word} (phishing indicator)")
                else:
                    st.write(f"🟢 {word} (legitimate indicator)")
        else:
            st.write("No significant indicators detected.")
    else:
        st.warning("Please enter some text to analyse.")