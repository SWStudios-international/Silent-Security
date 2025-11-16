==============================================================
Silent Sentinel 2.0 – Real-Time Network Monitoring GUI
==============================================================

Silent Sentinel 2.0 is a next-generation, real-time network monitoring
and AI-assisted analysis tool. It captures live network traffic, identifies
anomalies, and offers actionable insights via a sleek Tkinter-based GUI and
interactive trend dashboards. Designed for cybersecurity enthusiasts,
students, and professionals who want a SOC-style monitoring experience
on their desktop.

--------------------------------------------------------------
Features
--------------------------------------------------------------
- Real-Time Packet Monitoring
  Capture live network traffic with detailed info: source, destination,
  protocol, port, and anomaly status.

- AI Prediction Console
  Provides intelligent summaries, recommendations, and guidance
  on suspicious activity.

- Trend Dashboard
  Real-time SOC-style protocol graphs with interactive hover-over tooltips
  and clickable bars to drill into packet logs.

- Tooltip Interface
  Hover over graph bars to see protocol counts, anomaly numbers,
  and recent activity, keeping the main console clean.

- Automated System Scan
  Scans critical directories (e.g., Documents, Windows, Program Files)
  every 5 minutes for unusual files or changes.

- Multi-Language Support
  Switch between supported languages in real time for localized monitoring.

- User-Friendly GUI
  Easy login, monitoring, and settings panels. Sleek dark theme with
  optional light theme.

- Learning Journal Integration
  Logs all AI suggestions, user inputs, summaries, and system scans in
  learning_journal.txt for review and analysis.

--------------------------------------------------------------
Installation
--------------------------------------------------------------
1. Clone the Repository
   git clone https://github.com/yourusername/silent-sentinel.git
   cd silent-sentinel

2. Install Requirements
   Make sure you have Python 3.13+ installed, then:
   pip install -r requirements.txt

   Required packages: tkinter, matplotlib, pillow, plus dependencies
   from sentinel_core, sentinel_sniffer, silent_sentinel_lang, and
   learning_journal.

3. Add Assets
   Place silent_sentinel.png in the root folder for the GUI logo.

--------------------------------------------------------------
Usage
--------------------------------------------------------------
1. Launch GUI
   python silent_sentinel_gui.py

2. Login or Register
   Enter your credentials or register a new account.

3. Start Monitoring
   - Click "Start Monitoring" to begin capturing packets.
   - Click "Bootstrap" to initialize modules and AI learning.

4. Interactive Analysis
   - Hover over trend bars to see protocol info and anomalies.
   - Click bars to drill down into recent packet logs.
   - AI Prediction Console provides actionable insights.

5. Stop Monitoring
   Click "Stop Monitoring" to safely halt packet capture.

6. Settings Panel
   Customize theme, language, and other preferences from the Settings menu.

--------------------------------------------------------------
Project Structure
--------------------------------------------------------------
silent_sentinel/
│
├─ silent_sentinel_gui.py     # Main GUI script
├─ sentinel_core.py           # Core system functions
├─ sentinel_sniffer.py        # Packet capture and analysis
├─ silent_sentinel_lang.py    # Language support
├─ learning_journal.py        # Logs AI suggestions and user input
├─ silent_sentinel.png        # Logo asset
└─ requirements.txt           # Python dependencies

--------------------------------------------------------------
Contributing
--------------------------------------------------------------
- Open issues for bugs or feature requests.
- Submit pull requests for improvements, features, or bug fixes.
- Keep consistent code style and update documentation when modifying behavior.

--------------------------------------------------------------
License
--------------------------------------------------------------
MIT License – see LICENSE for details.

--------------------------------------------------------------
Acknowledgements
--------------------------------------------------------------
- Inspired by SOC dashboards and cybersecurity monitoring tools.
- Built with Python, Tkinter, and Matplotlib.
- Lightweight AI logic integrated for intelligent guidance and packet summaries.
