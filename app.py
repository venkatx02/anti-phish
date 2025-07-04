from flask import Flask, render_template, request
import pickle
import pandas as pd
import os
from dotenv import load_dotenv
from feature_extractor import extract_features

load_dotenv()

app = Flask(__name__)
xgbModel = pickle.load(open("xgbModel.pkl", "rb"))

@app.route('/', methods=['GET'])
def main():
    return render_template('index.html')

@app.route('/', methods=['POST'])
def predict():
    url = request.form['urllink']
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        features = extract_features(url)
        feature_names = [
            'length_url', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at',
            'nb_slash', 'nb_dslash', 'https_token', 'ratio_digits_url',
            'prefix_suffix', 'shortening_service', 'nb_hyperlinks',
            'iframe', 'right_clic', 'domain_with_copyright',
            'whois_registered_domain', 'domain_registration_length',
            'domain_age', 'web_traffic', 'dns_record', 'google_index', 'page_rank'
        ]
        feature_frame = pd.DataFrame([features], columns=feature_names)
        pred = xgbModel.predict(feature_frame)
        proba = xgbModel.predict_proba(feature_frame)

        classification_label = "Benign" if pred[0] == 0 else "Phishing"
        confidence = round(proba[0][pred[0]] * 100, 2)

    except Exception as e:
        classification_label = "Error"
        confidence = 0.0
        print(f"Error during prediction: {e}")

    return render_template(
        'index.html',
        classification=classification_label,
        confidence=confidence,
        urllink=url
    )

if __name__ == '__main__':
    app.run(port=3000, debug=True)