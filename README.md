# 🛡️ SentriX — Host-Based Intrusion Detection & Automated Response System

SentriX is a modular host-based intrusion detection and automated response system designed to monitor Linux systems, detect suspicious behavior, evaluate security risks, and automatically mitigate threats in real time.

This project focuses on building a production-style defensive cybersecurity pipeline by combining telemetry collection, behavioral analysis, machine learning scoring, and automated response mechanisms.

---

## 🚀 Project Scope

SentriX is designed to protect Linux machines and servers by providing:

- Continuous SSH authentication monitoring  
- File integrity verification  
- Process behavior tracking  
- Risk-based threat scoring  
- Automated attack response  
- Real-time alerts and visualization  

The system supports standalone host deployment as well as LAN-based multi-machine monitoring architecture.

---

## 🧠 What SentriX Does

SentriX works as a layered security pipeline:

### 🔐 Authentication Monitoring
- Tracks SSH login attempts  
- Detects brute-force and abnormal login behavior  
- Assigns risk scores to authentication events  

### 📁 File Integrity Monitoring
- Monitors sensitive system files  
- Detects unauthorized modifications  
- Flags suspicious file activity  

### ⚙ Process Behavior Monitoring
- Tracks running processes  
- Analyzes runtime behavior patterns  
- Detects stealthy or malicious activity  

### 📊 Risk Scoring Engine
- Combines detection outputs  
- Generates unified risk score  
- Applies confidence thresholds  

### 🚨 Automated Response System
- Blocks malicious IP addresses  
- Terminates malicious processes  
- Applies firewall rules automatically  

### 📈 Logging & Visualization
- Stores forensic logs  
- Sends real-time alerts  
- Displays system security status  

---

## 🏗 System Architecture

SentriX follows a multi-layered pipeline:

```
Monitoring Layer
        ↓
Feature Processing Layer
        ↓
Detection Models
        ↓
Risk Scoring Engine
        ↓
Decision & Response Layer
        ↓
Alerts, Logs & Dashboard
```

Each module is independently designed to ensure scalability, modularity, and maintainability.

---

## 📁 Project Structure

```
SentriX/
├── alerts/
│   ├── logger.py
│   └── telegram_alert.py
├── config/
│   └── settings.py
├── dashboard/
│   └── app.py
├── detector/
│   ├── file_integrity.py
│   ├── privilege_monitor.py
│   └── ssh_detector.py
├── logs/
├── ml_engine/
│   ├── ensemble_scoring.py
│   ├── ngram_extractor.py
│   └── temporal_features.py
├── models/
├── responder/
│   ├── firewall.py
│   └── process_control.py
├── utils/
│   └── helpers.py
├── main.py
├── requirements.txt
└── README.md
```

---

## ⚙ Deployment Mode

SentriX supports:

- Single Linux machine deployment  
- Server security hardening  
- LAN-based multi-host monitoring  
- Centralized alert dashboard  

---

## 🎯 Use Cases

- Linux server protection  
- SSH brute-force detection  
- Malware behavior analysis  
- Insider threat monitoring  
- Academic cybersecurity research  
- Resume and portfolio project  

---

## 🧪 Development Status

Current implementation includes:

- Monitoring modules complete  
- Feature extraction pipeline active  
- Risk scoring engine integrated  
- Automated response modules operational  
- Alerting and dashboard ready  

---

## 👥 Contributors

**Core System Design & Security Pipeline Integration**  
- [val3nt1ne-d4c](https://github.com/val3nt1ne-d4c)

**Machine Learning Model Development**  
- [saarthak354](https://github.com/saarthak354)

---

## ⚠ Disclaimer

This project is strictly intended for educational and defensive security research purposes only.  
Unauthorized deployment against systems without permission is illegal.

---

## ⭐ Why SentriX Matters

SentriX demonstrates:

- Real-world defensive security engineering  
- Modular cybersecurity system design  
- Detection + Response automation  
- Production-style security architecture  

This project is designed to reflect industry-grade IDS architecture rather than simple scripts.

---

## 📌 Planned Enhancements

- Multi-agent centralized management  
- Web-based admin panel  
- False-positive tuning interface  
- Advanced threat profiling  
- Cloud deployment support  

---

If you find this project useful, consider giving it a ⭐ on GitHub.
