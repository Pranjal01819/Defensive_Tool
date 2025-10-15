from flask import Flask, request, jsonify
from flask_cors import CORS
import re
from urllib.parse import urlparse
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import pickle
import os

app = Flask(__name__)
CORS(app)

class SimplePhishingDetector:
    def __init__(self):
        self.model = None
        self.load_or_train_model()
    
    def extract_simple_features(self, url):
        """Extract 8 SIMPLE, easy-to-explain features"""
        features = []
        feature_details = {}
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            full_url = url.lower()
            
            # Feature 1: URL Length (longer = more suspicious)
            url_length = len(full_url)
            features.append(url_length)
            feature_details['url_length'] = {
                'value': url_length,
                'suspicious': url_length > 75,
                'risk': 'high' if url_length > 100 else 'medium' if url_length > 75 else 'low'
            }
            
            # Feature 2: Has HTTPS (secure = good)
            has_https = 1 if parsed.scheme == 'https' else 0
            features.append(has_https)
            feature_details['has_https'] = {
                'value': has_https,
                'suspicious': has_https == 0,
                'risk': 'high' if has_https == 0 else 'safe'
            }
            
            # Feature 3: Number of dots in domain (more dots = suspicious subdomains)
            dots_count = domain.count('.')
            features.append(dots_count)
            feature_details['dots_count'] = {
                'value': dots_count,
                'suspicious': dots_count > 3,
                'risk': 'high' if dots_count > 4 else 'medium' if dots_count > 3 else 'low'
            }
            
            # Feature 4: Has IP address instead of domain name
            has_ip = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0
            features.append(has_ip)
            feature_details['has_ip'] = {
                'value': has_ip,
                'suspicious': has_ip == 1,
                'risk': 'high' if has_ip == 1 else 'safe'
            }
            
            # Feature 5: Suspicious keywords (login, verify, account, etc.)
            keywords = ['login', 'verify', 'account', 'update', 'secure', 'banking']
            keyword_count = sum(1 for word in keywords if word in full_url)
            features.append(keyword_count)
            feature_details['suspicious_keywords'] = {
                'value': keyword_count,
                'suspicious': keyword_count > 1,
                'risk': 'high' if keyword_count > 2 else 'medium' if keyword_count > 0 else 'low'
            }
            
            # Feature 6: Has @ symbol (can hide real domain)
            has_at = 1 if '@' in full_url else 0
            features.append(has_at)
            feature_details['has_at_symbol'] = {
                'value': has_at,
                'suspicious': has_at == 1,
                'risk': 'high' if has_at == 1 else 'safe'
            }
            
            # Feature 7: Too many hyphens in domain
            hyphen_count = domain.count('-')
            features.append(hyphen_count)
            feature_details['hyphen_count'] = {
                'value': hyphen_count,
                'suspicious': hyphen_count > 2,
                'risk': 'high' if hyphen_count > 3 else 'medium' if hyphen_count > 1 else 'low'
            }
            
            # Feature 8: Suspicious domain extension
            suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top']
            tld = domain.split('.')[-1] if '.' in domain else ''
            has_suspicious_tld = 1 if tld in suspicious_tlds else 0
            features.append(has_suspicious_tld)
            feature_details['suspicious_tld'] = {
                'value': has_suspicious_tld,
                'suspicious': has_suspicious_tld == 1,
                'risk': 'high' if has_suspicious_tld == 1 else 'safe'
            }
            
        except Exception as e:
            print(f"Error: {e}")
            features = [0] * 8
            feature_details = {}
        
        return features, feature_details
    
    def load_or_train_model(self):
        """Load or train the ML model"""
        model_path = 'simple_phishing_model.pkl'
        
        if os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                print("✓ Model loaded")
                return
            except:
                print("Training new model...")
        
        # Generate training data
        X_train, y_train = self.generate_training_data()
        
        # Train Random Forest (ensemble of decision trees)
        self.model = RandomForestClassifier(
            n_estimators=50,  # 50 decision trees
            max_depth=8,
            random_state=42
        )
        self.model.fit(X_train, y_train)
        
        # Save model
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        print("✓ Model trained and saved")
    
    def generate_training_data(self):
        """Create training examples"""
        X = []
        y = []
        
        # 500 Safe URLs
        safe_urls = [
            'https://www.google.com',
            'https://github.com',
            'https://stackoverflow.com',
            'https://www.amazon.com',
            'https://www.microsoft.com'
        ]
        
        for _ in range(500):
            url = np.random.choice(safe_urls) + f'/page{np.random.randint(100)}'
            features, _ = self.extract_simple_features(url)
            X.append(features)
            y.append(0)  # Safe
        
        # 500 Phishing URLs
        phishing_urls = [
            'http://192.168.1.1/login-verify',
            'http://secure-login-verify.tk',
            'http://account-suspended.ml',
            'http://user@evil-site.com',
            'http://paypal-security-update.xyz'
        ]
        
        for _ in range(500):
            url = np.random.choice(phishing_urls) + f'?id={np.random.randint(1000)}'
            features, _ = self.extract_simple_features(url)
            X.append(features)
            y.append(1)  # Phishing
        
        return np.array(X), np.array(y)
    
    def predict(self, url):
        """Predict if URL is phishing"""
        features, feature_details = self.extract_simple_features(url)
        features_array = np.array(features).reshape(1, -1)
        
        prediction = self.model.predict(features_array)[0]
        probability = self.model.predict_proba(features_array)[0]
        
        return {
            'is_phishing': int(prediction),
            'confidence': float(probability[1] * 100),
            'features': feature_details
        }

# Initialize detector
detector = SimplePhishingDetector()

@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    """Analyze URL endpoint"""
    try:
        data = request.get_json()
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'URL required'}), 400
        
        result = detector.predict(url)
        
        return jsonify({
            'success': True,
            'prediction': result
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    print("=" * 50)
    print("🚀 Starting Simple Phishing Detector")
    print("=" * 50)
    print("🌐 Running on: http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, port=5000)
