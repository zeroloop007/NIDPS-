from flask import Flask, render_template, request, jsonify
import pandas as pd
import numpy as np
from tensorflow.keras.models import model_from_json
import os
import json

app = Flask(__name__)

# Configure paths
MODEL_PATH = 'models/mlp_multi.json'
WEIGHTS_PATH = 'models/mlp_multi.weights.h5'

# Directory for uploaded files
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create folder if it doesn't exist

# Class labels and their classification
CLASSES = ['Dos', 'normal', 'Probe', 'R2L', 'U2R']
ABNORMAL_TYPES = ['Dos', 'Probe', 'R2L', 'U2R']
CONFIDENCE_THRESHOLD = 70.0  # Threshold for abnormal classification

# Define the expected features (rest of the features remain the same)
FEATURE_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
] + [f'additional_feature_{i}' for i in range(52)]

def load_model():
    """Load the trained MLP model."""
    try:
        with open(MODEL_PATH, 'r') as json_file:
            loaded_model_json = json_file.read()
        model = model_from_json(loaded_model_json)
        model.load_weights(WEIGHTS_PATH)
        model.compile(loss='categorical_crossentropy', 
                      optimizer='adam', 
                      metrics=['accuracy'])
        return model
    except Exception as e:
        raise Exception(f"Error loading model: {str(e)}")

def predict_traffic(data):
    """Make predictions on network traffic data with confidence threshold."""
    try:
        model = load_model()
        predictions = model.predict(data)
        
        results = []
        for pred in predictions:
            class_idx = np.argmax(pred)
            confidence = pred[class_idx] * 100
            traffic_type = CLASSES[class_idx]
            
            # Determine classification based on type and confidence
            if traffic_type in ABNORMAL_TYPES and confidence >= CONFIDENCE_THRESHOLD:
                classification = 'abnormal'
            else:
                classification = 'normal'
            
            result = {
                'traffic_type': traffic_type,
                'classification': classification
            }
            results.append(result)
        
        return results
    
    except Exception as e:
        raise Exception(f"Error in prediction: {str(e)}")

def preprocess_data(data):
    """Preprocess input data to match model requirements."""
    try:
        if isinstance(data, (list, dict)):
            if isinstance(data, list):
                data = pd.DataFrame(data)
            else:
                data = pd.DataFrame([data])
        
        for feature in FEATURE_NAMES:
            if feature not in data.columns:
                data[feature] = 0
        
        data = data[FEATURE_NAMES]
        
        categorical_features = ['protocol_type', 'service', 'flag']
        for feature in categorical_features:
            if feature in data.columns:
                data[feature] = pd.Categorical(data[feature]).codes
        
        return data.astype('float32')
    
    except Exception as e:
        raise Exception(f"Error in preprocessing: {str(e)}\nData shape: {data.shape}\nColumns: {data.columns.tolist()}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze-file', methods=['POST'])
def analyze_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    filepath = None  # Initialize filepath
    try:
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        if file.filename.endswith('.csv'):
            data = pd.read_csv(filepath)
        elif file.filename.endswith('.json'):
            with open(filepath, 'r') as f:
                data = json.load(f)
        else:
            return jsonify({'error': 'Unsupported file format. Use CSV or JSON'}), 400

        processed_data = preprocess_data(data)
        results = predict_traffic(processed_data)

        # Remove the file after processing
        os.remove(filepath)

        return jsonify({
            'timestamp': pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S'),
            'results': results
        })
    
    except Exception as e:
        # Safely remove the file if it was saved
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': f'Error processing file: {str(e)}'}), 500

if __name__ == '__main__':
    if not (os.path.isfile(MODEL_PATH) and os.path.isfile(WEIGHTS_PATH)):
        raise Exception(
            "Model files not found. Please ensure the model and weights "
            "files are in the correct locations:\n"
            f"Model: {MODEL_PATH}\n"
            f"Weights: {WEIGHTS_PATH}"
        )
    
    app.run(debug=True)
