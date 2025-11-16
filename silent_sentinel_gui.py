import tkinter as tk
from tkinter import messagebox, colorchooser
from PIL import Image, ImageTk
import random
import json
import os

# --- Main Window ---
root = tk.Tk()
root.title("Silent Sentinel")
root.geometry("400x500")
root.resizable(False, False)

CREDENTIALS_FILE = "credentials.json"

# --- Themes ---
dark_theme = {"bg": "#0d0d0d", "fg": "#39ff14", "entry_bg": "#1a1a1a",
              "btn_bg": "#111111", "btn_fg": "#39ff14", "panel_bg": "#0a0a0a"}
light_theme = {"bg": "#f0f0f0", "fg": "#0d0d0d", "entry_bg": "#ffffff",
               "btn_bg": "#dddddd", "btn_fg": "#0d0d0d", "panel_bg": "#e0e0e0"}
theme = dark_theme

# --- Helper Functions ---
def save_credentials(users):
    with open(CREDENTIALS_FILE, "w") as f:
        json.dump(users, f)

def load_credentials():
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as f:
            return json.load(f)
    return {}

# --- Hover glow ---
def on_enter(e):
    e.widget.config(bg="#39ff14", fg="#0d0d0d")

def on_leave(e):
    e.widget.config(bg=theme["btn_bg"], fg=theme["btn_fg"])

# --- Logging ---
def log(message):
    output_text.config(state="normal")
    output_text.insert(tk.END, message + "\n")
    output_text.see(tk.END)
    output_text.config(state="disabled")

# --- Load logo ---
image = Image.open("silent_sentinel.png")
image = image.resize((250, 250), Image.Resampling.LANCZOS)
photo = ImageTk.PhotoImage(image)

# --- Frames ---
frames = {}
for name in ["login", "register", "monitor", "dashboard", "settings"]:
    f = tk.Frame(root, bg=theme["bg"])
    f.place(x=0, y=0, relwidth=1, relheight=1)
    frames[name] = f

# --- Theme apply ---
def apply_theme(widget_list):
    for widget in widget_list:
        if isinstance(widget, tk.Label):
            widget.config(bg=theme["bg"], fg=theme["fg"])
        elif isinstance(widget, tk.Entry):
            widget.config(bg=theme["entry_bg"], fg=theme["fg"], insertbackground=theme["fg"])
        elif isinstance(widget, tk.Button):
            widget.config(bg=theme["btn_bg"], fg=theme["btn_fg"],
                          activebackground=theme["btn_bg"], activeforeground=theme["btn_fg"])
    root.config(bg=theme["bg"])

# --- Matrix Animation ---
matrix_text = "SILENT SENTINEL"
matrix_drops = [random.randint(0, 20) for _ in range(40)]

def animate_matrix(canvas, drops):
    canvas.delete("all")
    # Circuit overlays
    for _ in range(12):
        x1, y1 = random.randint(0, 400), random.randint(0, 500)
        x2, y2 = x1 + random.randint(20, 50), y1 + random.randint(0, 20)
        pulse = random.randint(100, 255)
        canvas.create_line(x1, y1, x2, y2, fill=f"#00{pulse:02x}99", width=1)
    # Falling letters
    for i in range(len(drops)):
        char = matrix_text[i % len(matrix_text)]
        if random.random() < 0.05:
            char = random.choice("!@#$%^&*")
        x = i * 10
        y = drops[i] * 15
        canvas.create_text(x, y, text=char, fill="#39ff14", font=("Courier", 10, "bold"))
        drops[i] = (drops[i] + 1) % 35
    # Glitch effect
    if random.random() < 0.02:
        canvas.create_rectangle(0, 0, 400, 500, fill="#00ff33", outline="")
    canvas.after(100, animate_matrix, canvas, drops)

# --- Login Frame ---
login_frame = frames["login"]

tk.Label(login_frame, image=photo, bg=theme["bg"]).pack(pady=(20, 10))
tk.Label(login_frame, text="Username:", font=("Courier", 12), bg=theme["bg"], fg=theme["fg"]).pack()
username_entry = tk.Entry(login_frame, font=("Courier", 12), bg=theme["entry_bg"], fg=theme["fg"],
                          insertbackground=theme["fg"], relief="solid", bd=2)
username_entry.pack(pady=(0,5))
tk.Label(login_frame, text="Password:", font=("Courier", 12), bg=theme["bg"], fg=theme["fg"]).pack()
password_entry = tk.Entry(login_frame, font=("Courier", 12), bg=theme["entry_bg"], fg=theme["fg"],
                          show="*", insertbackground=theme["fg"], relief="solid", bd=2)
password_entry.pack(pady=(0,10))
error_label = tk.Label(login_frame, text="", font=("Courier", 10), bg=theme["bg"], fg="red")
error_label.pack(pady=(0,10))

# Buttons container
btn_container = tk.Frame(login_frame, bg=theme["bg"])
btn_container.pack(pady=5, fill="x")
login_btn = tk.Button(btn_container, text="Login", font=("Courier", 12, "bold"),
                      command=lambda: authenticate_user(), bg=theme["btn_bg"], fg=theme["btn_fg"], bd=4, relief="raised")
login_btn.pack(fill="x", pady=(0,5))
login_btn.bind("<Enter>", on_enter)
login_btn.bind("<Leave>", on_leave)

register_btn = tk.Button(btn_container, text="Register New Account", font=("Courier", 10),
                         bg=theme["btn_bg"], fg=theme["btn_fg"], bd=3, relief="raised",
                         command=lambda: frames["register"].tkraise())
register_btn.pack(fill="x")
register_btn.bind("<Enter>", on_enter)
register_btn.bind("<Leave>", on_leave)

# --- Register Frame ---
register_frame = frames["register"]
tk.Label(register_frame, text="Register New Account", font=("Courier", 14, "bold"),
         bg=theme["bg"], fg=theme["fg"]).pack(pady=20)
reg_username = tk.Entry(register_frame, font=("Courier", 12), bg=theme["entry_bg"], fg=theme["fg"])
reg_username.pack(pady=5)
reg_password = tk.Entry(register_frame, font=("Courier", 12), bg=theme["entry_bg"], fg=theme["fg"], show="*")
reg_password.pack(pady=5)
reg_error = tk.Label(register_frame, text="", font=("Courier", 10), bg=theme["bg"], fg="red")
reg_error.pack(pady=5)

tk.Button(register_frame, text="Register", font=("Courier", 12, "bold"),
          bg=theme["btn_bg"], fg=theme["btn_fg"], bd=4, relief="raised",
          command=lambda: register_user()).pack(pady=10)
tk.Button(register_frame, text="Back to Login", font=("Courier", 12, "bold"),
          bg=theme["btn_bg"], fg=theme["btn_fg"], bd=4, relief="raised",
          command=lambda: frames["login"].tkraise()).pack(pady=5)

# --- Functions ---
def authenticate_user():
    username = username_entry.get().strip()
    password = password_entry.get().strip()
    users = load_credentials()
    if username == "admin" and password == "matrix":
        frames["monitor"].tkraise()
        return
    if username in users and users[username] == password:
        frames["monitor"].tkraise()
    else:
        error_label.config(text="Invalid credentials!")

def register_user():
    username = reg_username.get().strip()
    password = reg_password.get().strip()
    if not username or not password:
        reg_error.config(text="Fill in all fields!")
        return
    users = load_credentials()
    if username in users:
        reg_error.config(text="Username already exists!")
        return
    users[username] = password
    save_credentials(users)
    reg_error.config(fg="green", text="Account created!")
    root.after(1000, lambda: frames["login"].tkraise())

# --- Monitor Frame ---
monitor_frame = frames["monitor"]
tk.Label(monitor_frame, image=photo, bg=theme["bg"]).pack(pady=20)
tk.Button(monitor_frame, text="Start Monitoring", font=("Courier", 12, "bold"),
          bg=theme["btn_bg"], fg=theme["btn_fg"], bd=4, relief="raised",
          command=lambda: frames["dashboard"].tkraise()).pack(pady=50)

# --- Dashboard Frame ---
dashboard_frame = frames["dashboard"]
dashboard_canvas = tk.Canvas(dashboard_frame, width=400, height=500, bg=theme["bg"], highlightthickness=0)
dashboard_canvas.place(x=0, y=0, relwidth=1, relheight=1)
animate_matrix(dashboard_canvas, matrix_drops)

# Output panel
output_frame = tk.Frame(dashboard_frame, bg=theme["panel_bg"], bd=3, relief="groove")
output_frame.place(x=20, y=200, width=360, height=200)
output_text = tk.Text(output_frame, bg="#0d0d0d", fg="#39ff14", font=("Courier", 10),
                      state="disabled", bd=0)
output_text.pack(fill="both", expand=True)
scrollbar = tk.Scrollbar(output_frame)
scrollbar.pack(side="right", fill="y")
output_text.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=output_text.yview)

# Dashboard Buttons
button_frame = tk.Frame(dashboard_frame, bg=theme["bg"])
button_frame.place(x=0, y=420, relwidth=1, height=50)

def start_monitoring():
    log("Monitoring started...")
    messagebox.showinfo("Monitoring", "Monitoring started!")

def view_logs():
    log("Logs displayed.")
    messagebox.showinfo("Logs", "Displaying logs...")

def open_settings():
    frames["settings"].tkraise()

def save_settings():
    user = username_entry.get().strip()
    pwd = password_entry.get().strip()
    save_credentials({user: pwd})
    messagebox.showinfo("Settings", "Credentials saved!")

buttons_info = [
    ("Start Monitoring", start_monitoring),
    ("View Logs", view_logs),
    ("Settings", open_settings),
    ("Exit", root.quit)
]

for text, cmd in buttons_info:
    btn = tk.Button(button_frame, text=text, font=("Courier", 10, "bold"),
                    bg=theme["btn_bg"], fg=theme["btn_fg"], bd=4, relief="raised", command=cmd)
    btn.pack(side="left", expand=True, fill="both", padx=5, pady=5)
    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)

# --- Settings Frame ---
settings_frame = frames["settings"]
tk.Label(settings_frame, text="Settings Panel", font=("Courier", 14, "bold"),
         bg=theme["bg"], fg=theme["fg"]).pack(pady=20)
save_btn = tk.Button(settings_frame, text="Save Credentials", font=("Courier", 12, "bold"),
                     bg=theme["btn_bg"], fg=theme["btn_fg"], bd=4, relief="raised", command=save_settings)
save_btn.pack(pady=10)
save_btn.bind("<Enter>", on_enter)
save_btn.bind("<Leave>", on_leave)
tk.Button(settings_frame, text="Back to Dashboard", font=("Courier", 12, "bold"),
          bg=theme["btn_bg"], fg=theme["btn_fg"], bd=4, relief="raised",
          command=lambda: frames["dashboard"].tkraise()).pack(pady=10)

# --- Theme Toggle ---
def toggle_theme():
    global theme
    theme = light_theme if theme == dark_theme else dark_theme
    apply_theme(root.winfo_children())

theme_btn = tk.Button(root, text="Toggle Dark/Light Mode", font=("Courier", 10),
                      command=toggle_theme, bg=theme["btn_bg"], fg=theme["btn_fg"], bd=4, relief="raised")
theme_btn.place(x=120, y=470)
theme_btn.bind("<Enter>", on_enter)
theme_btn.bind("<Leave>", on_leave)

# --- Start ---
frames["login"].tkraise()
apply_theme(root.winfo_children())
root.mainloop()
