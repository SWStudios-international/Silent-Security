import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
from sentinel_core import start_sentinel, stop_sentinel
from silent_sentinel_lang import _, set_language, get_current_lang, supported_languages
from sentinel_sniffer import NetworkSniffer
from learning_journal import LearningJournal
from datetime import datetime

journal = LearningJournal("learning_journal.txt")

class SilentSentinelGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Silent Sentinel 3.1 Beta 1.5")
        self.root.geometry("1300x750")
        self.root.configure(bg="#2b2b2b")
        self.logged_in = False
        self.user = None

        self.lang_var = tk.StringVar(value=get_current_lang())

        # Packet tracking
        self.packet_count = 0
        self.packet_summary = []

        # Setup frames and logo
        self.setup_frames()
        self.load_logo()

        # Login screen
        self.show_login_screen()

        # Tooltip support
        self.tooltip = None

    # -------------------- UI Setup --------------------
    def setup_frames(self):
        self.left_frame = tk.Frame(self.root, bg="#2b2b2b")
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.right_frame = tk.Frame(self.root, bg="#1e1e1e", width=400)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.Y)

        # Menu bar
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)

        # File menu
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label=_("exit"), command=self.root.quit)
        self.menu_bar.add_cascade(label=_("exit"), menu=self.file_menu)

        # Settings menu
        self.settings_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.settings_menu.add_command(label=_("settings"), command=self.open_settings)
        self.menu_bar.add_cascade(label=_("settings"), menu=self.settings_menu)

        # Language menu
        self.lang_menu = tk.Menu(self.menu_bar, tearoff=0)
        for code, name in supported_languages():
            self.lang_menu.add_command(label=name, command=lambda c=code: self.change_language(c))
        self.menu_bar.add_cascade(label="Language", menu=self.lang_menu)

    def load_logo(self):
        logo = Image.open("silent_sentinel.png").resize((150, 150))
        self.logo_img = ImageTk.PhotoImage(logo)

    # -------------------- Login --------------------
    def show_login_screen(self):
        self.login_frame = tk.Frame(self.left_frame, bg="#2b2b2b")
        self.login_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        tk.Label(self.login_frame, image=self.logo_img, bg="#2b2b2b").pack(pady=20)
        tk.Label(self.login_frame, text=_("login"), fg="white", bg="#2b2b2b", font=("Arial", 14)).pack(pady=5)
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.pack(pady=5)
        tk.Label(self.login_frame, text=_("password"), fg="white", bg="#2b2b2b", font=("Arial", 14)).pack(pady=5)
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.pack(pady=5)

        btn_frame = tk.Frame(self.login_frame, bg="#2b2b2b")
        btn_frame.pack(pady=10)
        login_btn = tk.Button(btn_frame, text=_("login"), command=self.login)
        login_btn.pack(side=tk.LEFT, padx=5)
        self.create_tooltip(login_btn, "Login with your credentials.")
        register_btn = tk.Button(btn_frame, text=_("register"), command=self.register)
        register_btn.pack(side=tk.LEFT, padx=5)
        self.create_tooltip(register_btn, "Register a new user account.")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username and password:
            self.logged_in = True
            self.user = username
            self.login_frame.destroy()
            self.show_monitoring_screen()
        else:
            messagebox.showwarning(_("error"), _("please_enter_credentials"))

    def register(self):
        messagebox.showinfo(_("register"), _("register"))

    # -------------------- Monitoring --------------------
    def show_monitoring_screen(self):
        # Packet Treeview
        cols = ("Time", "Src", "Dst", "Protocol", "Port", "Anomaly")
        self.tree = ttk.Treeview(self.left_frame, columns=cols, show="headings")
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120 if col != "Time" else 140)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Buttons
        btn_frame = tk.Frame(self.left_frame, bg="#2b2b2b")
        btn_frame.pack(pady=5)
        self.start_btn = tk.Button(btn_frame, text=_("start_monitoring"), command=self.start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.create_tooltip(self.start_btn, "Start monitoring network traffic and log packets.")
        self.stop_btn = tk.Button(btn_frame, text=_("stop_monitoring"), command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.create_tooltip(self.stop_btn, "Stop monitoring network traffic.")
        self.bootstrap_btn = tk.Button(btn_frame, text=_("bootstrap"), command=self.bootstrap)
        self.bootstrap_btn.pack(side=tk.LEFT, padx=5)
        self.create_tooltip(self.bootstrap_btn, "Initialize system modules and AI learning.")

        # AI Prediction Console
        tk.Label(self.right_frame, text="AI Prediction Console", fg="white", bg="#1e1e1e", font=("Arial", 12, "bold")).pack(pady=5)
        self.ai_text = tk.Text(self.right_frame, bg="#2b2b2b", fg="white", height=35)
        self.ai_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        self.ai_entry = tk.Entry(self.right_frame, bg="#1e1e1e", fg="white")
        self.ai_entry.pack(fill=tk.X, padx=5, pady=5)
        self.ai_entry.bind("<Return>", self.send_ai_message)

        # Sniffer
        self.sniffer = NetworkSniffer(callback=self.process_packet)

    # -------------------- Packet Handling --------------------
    def process_packet(self, pkt):
        timestamp = datetime.now().strftime("%H:%M:%S")
        src = pkt.get("src", "")
        dst = pkt.get("dst", "")
        proto = pkt.get("proto", "")
        port = pkt.get("port", "")
        anomaly = pkt.get("anomaly", False)

        # Insert into Treeview
        anomaly_str = "YES" if anomaly else "NO"
        self.tree.insert("", tk.END, values=(timestamp, src, dst, proto, port, anomaly_str))

        # Track packets
        self.packet_count += 1
        self.packet_summary.append(pkt)

        # Immediate alert for anomalies
        if anomaly:
            suggestion = f"Check port {port} from {src} immediately!"
            self.log_ai(f"[AI] {suggestion}")
            journal.record(f"AI suggestion: {suggestion}")

        # Generate summary every 200 packets
        if self.packet_count % 200 == 0:
            summary_msg = self.generate_summary(self.packet_summary)
            self.log_ai(f"[AI Summary] {summary_msg}")
            journal.record(f"AI summary: {summary_msg}")
            self.packet_summary = []

    def generate_summary(self, packets):
        total = len(packets)
        anomalies = [p for p in packets if p.get("anomaly")]
        protocols = {}
        for p in packets:
            proto = p.get("proto", "UNKNOWN")
            protocols[proto] = protocols.get(proto, 0) + 1

        summary = f"Processed {total} packets. "
        summary += f"{len(anomalies)} anomalies detected. "
        summary += "Traffic breakdown: " + ", ".join([f"{k}: {v}" for k,v in protocols.items()]) + "."
        return summary

    # -------------------- AI Interaction --------------------
    def send_ai_message(self, event):
        msg = self.ai_entry.get().strip()
        if not msg:
            return
        self.log_ai(f"[User] {msg}")
        journal.record(f"AI learning input: {msg}")
        response = self.ai_suggest(msg)
        self.log_ai(f"[AI] {response}")
        self.ai_entry.delete(0, tk.END)

    def ai_suggest(self, user_input):
        # Smarter suggestions: adaptive and predictive
        keywords = {
            "anomaly": "Consider checking unusual traffic patterns and potential port scans.",
            "port scan": "Recommend blocking suspicious IP addresses or throttling connections.",
            "ddos": "Suggest enabling rate limiting on the firewall and alerting the network team.",
            "ssh": "Monitor SSH login attempts; unusual spikes may indicate brute force attacks.",
            "http": "Check for unusual HTTP request rates that could indicate scraping or bot activity."
        }
        for key, suggestion in keywords.items():
            if key in user_input.lower():
                return suggestion
        return "Understood. Monitoring traffic trends for insights."

    def log_ai(self, msg):
        self.ai_text.insert(tk.END, f"{msg}\n")
        self.ai_text.see(tk.END)

    # -------------------- Control --------------------
    def start_monitoring(self):
        self.bootstrap()
        self.sniffer.start()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.log_ai("[System] Monitoring started.")

    def stop_monitoring(self):
        self.sniffer.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log_ai("[System] Monitoring stopped.")

    def bootstrap(self):
        self.log_ai("[System] Bootstrap complete.")
        journal.record("Bootstrap performed.")

    # -------------------- Settings --------------------
    def open_settings(self):
        if hasattr(self, "settings_win") and self.settings_win.winfo_exists():
            self.settings_win.lift()
            return
        self.settings_win = tk.Toplevel(self.root)
        self.settings_win.title(_("settings"))
        self.settings_win.geometry("400x400")
        self.settings_win.configure(bg="#2b2b2b")
        tk.Label(self.settings_win, text=_("Select Theme:"), bg="#2b2b2b", fg="white").pack(pady=5)
        theme_var = tk.StringVar(value="dark")
        tk.OptionMenu(self.settings_win, theme_var, "dark", "light").pack()
        tk.Label(self.settings_win, text=_("Select Language:"), bg="#2b2b2b", fg="white").pack(pady=5)
        lang_var = tk.StringVar(value=get_current_lang())
        menu = tk.OptionMenu(self.settings_win, lang_var, *[name for _, name in supported_languages()],
                             command=lambda v: self.change_language(self.lang_code_from_name(v)))
        menu.pack(pady=5)
        tk.Button(self.settings_win, text=_("settings"), command=self.settings_win.destroy).pack(pady=20)

    def change_language(self, code):
        set_language(code)
        self.lang_var.set(code)
        # Note: AI messages are in English for now; translation integration can be added if desired
        self.update_ui_texts()

    def update_ui_texts(self):
        self.start_btn.config(text=_("start_monitoring"))
        self.stop_btn.config(text=_("stop_monitoring"))
        self.bootstrap_btn.config(text=_("bootstrap"))

    def lang_code_from_name(self, name):
        for code, n in supported_languages():
            if n == name:
                return code
        return "en"

    # -------------------- Tooltip --------------------
    def create_tooltip(self, widget, text):
        def enter(event):
            if hasattr(self, 'tooltip') and self.tooltip:
                self.tooltip.destroy()
            self.tooltip = tk.Toplevel(self.root)
            self.tooltip.wm_overrideredirect(True)
            self.tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
            tk.Label(self.tooltip, text=text, bg="#ffffe0", fg="black", font=("Arial", 10)).pack()
        def leave(event):
            if hasattr(self, 'tooltip') and self.tooltip:
                self.tooltip.destroy()
                self.tooltip = None
        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)

if __name__ == "__main__":
    root = tk.Tk()
    gui = SilentSentinelGUI(root)
    root.mainloop()
