# 🛡️ CyberWatch – Windows Security Log Analyzer

## 📌 Project Overview

CyberWatch is a Python-based Windows Security Log Analyzer developed as a cybersecurity portfolio project. It reads Windows Security Event Logs, identifies important security events, classifies their risk levels, displays a security summary, and automatically generates a security report.

This project demonstrates the basic skills required for a Security Operations Center (SOC) Analyst, including log analysis, event classification, risk assessment, and security reporting.

---

## ✨ Features

- Reads Windows Security Event Logs
- Detects important Windows Event IDs
- Displays event meaning
- Shows colour-coded risk levels
- Generates a security summary
- Calculates an overall risk level
- Automatically creates a CyberWatch_Report.txt file

---

## 🛠️ Technologies Used

- Python 3.12
- pywin32
- colorama
- Windows Event Viewer

---

## 📂 Project Structure

```
CyberWatch
│── cyberwatch.py
│── CyberWatch_Report.txt
│── README.md
│── requirements.txt
│── screenshots
```

---

## 🚀 How to Run

1. Install Python 3.12
2. Install dependencies

```
pip install pywin32 colorama
```

3. Open Command Prompt or VS Code as Administrator.

4. Run

```
python cyberwatch.py
```

---

## 📸 Sample Output

The application displays:

- Total Security Events
- Event ID
- Event Meaning
- Risk Level
- Security Summary
- Overall Risk Level

It also automatically generates:

```
CyberWatch_Report.txt
```

---

## 📈 Future Improvements

- Export reports as PDF
- GUI interface
- Event filtering by date
- Advanced risk scoring
- Dashboard with charts

---

## 👨‍💻 Author

**Rishitha**

Master of Cybersecurity Student

La Trobe University