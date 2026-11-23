# 🛡️ AEGIS AI
### AI Enhanced Guard & Intelligence System

**An AI-Powered Cyber Threat Detection and Early Warning System**

## 1. Project Overview

AEGIS AI is an intelligent cybersecurity application designed to analyze network traffic and identify potentially malicious activities using Machine Learning.

The system uses a trained Random Forest classification model to classify network traffic and help identify suspicious activities. It provides an interactive dashboard for viewing predictions, analyzing traffic, monitoring threats, and reviewing detection history.

## 2. Key Features

- **Machine Learning-Based Detection:** Uses a trained Random Forest model to classify network traffic.
- **Threat Classification:** Identifies benign traffic and suspicious activities, including Bot, FTP-Patator, and SSH-Patator.
- **CSV Traffic Analysis:** Allows users to upload CSV files for batch analysis.
- **Early Warning System:** Provides NORMAL, ELEVATED, and CRITICAL warning levels based on suspicious traffic.
- **Interactive Dashboard:** Displays threat statistics, charts, and analysis results.
- **User Authentication:** Provides registration and login functionality with PostgreSQL database integration.
- **Threat History:** Maintains a record of previous detection results.
- **Test Samples:** Includes sample requests for testing different traffic categories.

## 3. Technology Stack

| Component | Technology |
|---|---|
| Frontend | HTML, CSS, JavaScript |
| Backend | Python, FastAPI |
| Machine Learning | Random Forest |
| Data Processing | Pandas |
| Model Management | Joblib |
| Database | PostgreSQL |
| API Server | Uvicorn |

## 4. Project Modules

1. User Authentication Module
2. Network Traffic Detection Module
3. CSV Upload and Analysis Module
4. Threat Classification Module
5. Early Warning Module
6. Dashboard and Analytics Module
7. Threat History Module

## 5. Project Structure

```text
MachineLearningCVE/
│
├── README.md
├── .gitignore
├── angis_final_model.pkl
│
└── angis-backend/
    ├── main.py
    ├── requirements.txt
    ├── features.json
    ├── feature.json
    ├── screenshots/
    │
    └── frontend/
        ├── landing.html
        ├── login.html
        ├── index.html
        ├── benign-test.json
        ├── bot-test.json
        ├── ftp-test.json
        └── ssh-test.json
```

## 6. Installation and Setup

### Prerequisites

- Python 3.10
- PostgreSQL
- Git

### Step 1: Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd MachineLearningCVE
```

### Step 2: Create a Virtual Environment

```bash
cd angis-backend
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Configure PostgreSQL

Configure PostgreSQL with the database and user expected by the backend:

- Database: `aegis_db`
- User: `aegis_app`

Set the database password as an environment variable:

```bash
export AEGIS_DB_PASSWORD="your_database_password"
```

Do not publish actual database passwords or credentials.

### Step 5: Start the Backend

From the `angis-backend` directory:

```bash
uvicorn main:app --reload
```

Backend address:

`http://127.0.0.1:8000`

API documentation:

`http://127.0.0.1:8000/docs`

### Step 6: Start the Frontend

Open another terminal in the `angis-backend` directory and run:

```bash
python -m http.server 3000 --directory frontend
```

Open:

`http://127.0.0.1:3000/landing.html`

## 7. Dataset

The project uses the CIC-IDS2017 network traffic dataset for its machine learning development and evaluation.

The dataset contains benign and malicious network traffic samples used to develop and evaluate the classification model.

Large original dataset files are not included in this GitHub repository.

## 8. Machine Learning Model

AEGIS AI uses a trained Random Forest classification model.

The model analyzes network traffic features and predicts the corresponding traffic category. Its predictions are presented through the dashboard for easier monitoring and analysis.

## 9. Future Scope

Future improvements may include real-time network traffic monitoring, advanced threat intelligence integration, automated incident response, and enhanced visualization.

## 10. Project Purpose

AEGIS AI aims to support cybersecurity monitoring by combining machine learning, traffic analysis, threat classification, and early warning capabilities in one interactive application.
