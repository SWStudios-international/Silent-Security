# silent_sentinel_lang.py

# Supported languages
languages = {
    "en": {
        "name": "English",
        "start_monitoring": "Start Monitoring",
        "stop_monitoring": "Stop Monitoring",
        "bootstrap": "Bootstrap System",
        "settings": "Settings",
        "exit": "Exit",
        "login": "Login",
        "register": "Register",
        "learning_milestones": "Learning Milestones",
        "ai_learning": "AI Learning",
        "error": "Error",
        "please_enter_credentials": "Please enter credentials."
    },
    "es": {
        "name": "Spanish",
        "start_monitoring": "Iniciar Monitoreo",
        "stop_monitoring": "Detener Monitoreo",
        "bootstrap": "Iniciar Sistema",
        "settings": "Configuración",
        "exit": "Salir",
        "login": "Iniciar Sesión",
        "register": "Registrar",
        "learning_milestones": "Hitos de Aprendizaje",
        "ai_learning": "Aprendizaje IA",
        "error": "Error",
        "please_enter_credentials": "Por favor ingrese las credenciales."
    },
    "de": {
        "name": "German",
        "start_monitoring": "Überwachung Starten",
        "stop_monitoring": "Überwachung Stoppen",
        "bootstrap": "System Starten",
        "settings": "Einstellungen",
        "exit": "Beenden",
        "login": "Anmelden",
        "register": "Registrieren",
        "learning_milestones": "Lernmeilensteine",
        "ai_learning": "KI Lernen",
        "error": "Fehler",
        "please_enter_credentials": "Bitte Zugangsdaten eingeben."
    },
    "zh": {
        "name": "Chinese",
        "start_monitoring": "开始监控",
        "stop_monitoring": "停止监控",
        "bootstrap": "初始化系统",
        "settings": "设置",
        "exit": "退出",
        "login": "登录",
        "register": "注册",
        "learning_milestones": "学习里程碑",
        "ai_learning": "AI 学习",
        "error": "错误",
        "please_enter_credentials": "请输入凭据。"
    },
    "pl": {
        "name": "Polish",
        "start_monitoring": "Rozpocznij Monitorowanie",
        "stop_monitoring": "Zatrzymaj Monitorowanie",
        "bootstrap": "Uruchom System",
        "settings": "Ustawienia",
        "exit": "Wyjdź",
        "login": "Zaloguj",
        "register": "Zarejestruj",
        "learning_milestones": "Kamienie Milowe Nauki",
        "ai_learning": "Uczenie AI",
        "error": "Błąd",
        "please_enter_credentials": "Proszę wprowadzić dane logowania."
    },
    "fr": {
        "name": "French",
        "start_monitoring": "Démarrer la Surveillance",
        "stop_monitoring": "Arrêter la Surveillance",
        "bootstrap": "Démarrer le Système",
        "settings": "Paramètres",
        "exit": "Quitter",
        "login": "Connexion",
        "register": "S’inscrire",
        "learning_milestones": "Étapes d’Apprentissage",
        "ai_learning": "Apprentissage IA",
        "error": "Erreur",
        "please_enter_credentials": "Veuillez entrer vos identifiants."
    }
}

# Default language code
current_lang_code = "en"

def _(key):
    """Translate a key using the current language code."""
    return languages.get(current_lang_code, {}).get(key, key)

def set_language(lang_code):
    """Set the current language by code (en, es, de...)."""
    global current_lang_code
    if lang_code in languages:
        current_lang_code = lang_code

def get_current_lang():
    """Return current language code."""
    return current_lang_code

def supported_languages():
    """Return list of (code, name) tuples for menus."""
    return [(code, info["name"]) for code, info in languages.items()]

#### Prototype v2.2b Lang Module ####
# Added support for French language