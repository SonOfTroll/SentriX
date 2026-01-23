# 🛡️ SentriX — Host-Based Intrusion Detection & Automated Response System

SentriX is a modular host-based security monitoring system designed to detect suspicious system behavior, analyze security risks, and automatically respond to threats in real time.

The project focuses on building a practical defensive security pipeline by combining system telemetry, behavioral analysis, risk scoring, and automated mitigation techniques.

---

## 🚀 Project Scope

SentriX is built to operate directly on Linux hosts and provides:

- Continuous monitoring of authentication activity  
- File integrity protection  
- Process behavior tracking  
- Risk-based threat evaluation  
- Automated response execution  
- Real-time alerting and visualization  

The system is designed for **local machines, servers, and LAN-based deployments** where centralized monitoring and fast response are required.

---

## 🧠 What SentriX Does

SentriX works as a multi-stage security pipeline:

### 1️⃣ Authentication Monitoring
- Tracks SSH login attempts  
- Detects abnormal access behavior  
- Assigns risk scores to login activity  

### 2️⃣ File Integrity Monitoring
- Monitors critical system files  
- Detects unauthorized modifications  
- Identifies suspicious content changes  

### 3️⃣ Process Behavior Monitoring
- Observes running processes  
- Analyzes execution patterns  
- Detects stealthy or abnormal activity  

### 4️⃣ Risk Scoring Engine
- Combines outputs from all detection modules  
- Generates a unified threat risk score  
- Prevents false positives through scoring thresholds  

### 5️⃣ Automated Response System
- Blocks malicious IP addresses  
- Terminates dangerous processes  
- Enforces security actions automatically  

### 6️⃣ Logging & Visualization
- Stores forensic logs  
- Sends instant alerts  
- Displays system status through dashboard  

---

## 🏗 System Architecture Overview

The system follows a layered pipeline architecture:

