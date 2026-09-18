import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import io
from typing import Optional, Callable
from PIL import Image, ImageTk

# Cybersecurity Palette
BG_DARK = "#0a0e17"
BG_CARD = "#111927"
BG_CARD_LIGHT = "#1e293b"
ACCENT_CYAN = "#00f2fe"
ACCENT_GREEN = "#10b981"
ACCENT_RED = "#ef4444"
ACCENT_AMBER = "#f59e0b"
TEXT_WHITE = "#f8fafc"
TEXT_MUTED = "#94a3b8"


class NetsentryClientUI:
    def __init__(
        self,
        local_ip: str,
        mac_address: str,
        hostname: str,
        on_register: Callable[[str, str], None],
        on_permission_response: Callable[[str, bool], None],
        on_stop_camera: Callable[[str], None],
        on_privacy_click: Callable[[], None]
    ):
        self.local_ip = local_ip
        self.mac_address = mac_address
        self.hostname = hostname

        self.on_register = on_register
        self.on_permission_response = on_permission_response
        self.on_stop_camera = on_stop_camera
        self.on_privacy_click = on_privacy_click

        self.active_session_uuid: Optional[str] = None
        self.remaining_seconds = 0
        self._timer_running = False

        self.root = tk.Tk()
        self.root.title("NETSENTRY Client - Network & Camera Node")
        self.root.geometry("520x680")
        self.root.minsize(480, 600)
        self.root.configure(bg=BG_DARK)

        self._build_ui()

    def _build_ui(self):
        # Header / Branding
        header_frame = tk.Frame(self.root, bg=BG_CARD, padx=20, pady=16)
        header_frame.pack(fill=tk.X)

        title_label = tk.Label(
            header_frame,
            text="NETSENTRY CLIENT",
            font=("Helvetica", 16, "bold"),
            fg=ACCENT_CYAN,
            bg=BG_CARD
        )
        title_label.pack(anchor=tk.W)

        sub_label = tk.Label(
            header_frame,
            text="Authorized Network Node & Consent-Driven Camera Agent",
            font=("Helvetica", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD
        )
        sub_label.pack(anchor=tk.W, pady=(2, 0))

        disclaimer_label = tk.Label(
            header_frame,
            text="⚠️ STRICTLY FOR AUTHORIZED LAB & DEFENSIVE IT USE • NOT FOR HACKERS OR SCAMMERS",
            font=("Helvetica", 8, "bold"),
            fg="#fbbf24",
            bg=BG_CARD
        )
        disclaimer_label.pack(anchor=tk.W, pady=(4, 0))

        # Main Container
        main_frame = tk.Frame(self.root, bg=BG_DARK, padx=20, pady=16)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Device Identity Card
        self._create_card_header(main_frame, "DEVICE IDENTITY")
        dev_card = tk.Frame(main_frame, bg=BG_CARD, padx=16, pady=12, highlightbackground=BG_CARD_LIGHT, highlightthickness=1)
        dev_card.pack(fill=tk.X, pady=(0, 14))

        self._create_info_row(dev_card, "Hostname:", self.hostname)
        self._create_info_row(dev_card, "Local IP:", self.local_ip)
        self._create_info_row(dev_card, "MAC Address:", self.mac_address)

        # Connection & Server Card
        self._create_card_header(main_frame, "SERVER CONNECTION")
        conn_card = tk.Frame(main_frame, bg=BG_CARD, padx=16, pady=12, highlightbackground=BG_CARD_LIGHT, highlightthickness=1)
        conn_card.pack(fill=tk.X, pady=(0, 14))

        # Server URL input
        url_frame = tk.Frame(conn_card, bg=BG_CARD)
        url_frame.pack(fill=tk.X, pady=4)
        tk.Label(url_frame, text="Server URL:", font=("Helvetica", 9, "bold"), fg=TEXT_MUTED, bg=BG_CARD, width=12, anchor=tk.W).pack(side=tk.LEFT)
        self.server_url_entry = tk.Entry(url_frame, font=("Consolas", 10), bg=BG_CARD_LIGHT, fg=TEXT_WHITE, insertbackground=TEXT_WHITE)
        self.server_url_entry.insert(0, "http://127.0.0.1:8000")
        self.server_url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Registration code input
        code_frame = tk.Frame(conn_card, bg=BG_CARD)
        code_frame.pack(fill=tk.X, pady=4)
        tk.Label(code_frame, text="Reg Code:", font=("Helvetica", 9, "bold"), fg=TEXT_MUTED, bg=BG_CARD, width=12, anchor=tk.W).pack(side=tk.LEFT)
        self.reg_code_entry = tk.Entry(code_frame, font=("Consolas", 10, "bold"), bg=BG_CARD_LIGHT, fg=ACCENT_CYAN, insertbackground=TEXT_WHITE)
        self.reg_code_entry.insert(0, "NET-XXXX-XXX")
        self.reg_code_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Status row & Connect Button
        btn_row = tk.Frame(conn_card, bg=BG_CARD)
        btn_row.pack(fill=tk.X, pady=(8, 0))

        self.status_badge = tk.Label(
            btn_row,
            text="● NOT CONNECTED",
            font=("Helvetica", 9, "bold"),
            fg=ACCENT_RED,
            bg=BG_CARD
        )
        self.status_badge.pack(side=tk.LEFT, pady=4)

        self.connect_btn = tk.Button(
            btn_row,
            text="Register & Connect",
            font=("Helvetica", 9, "bold"),
            bg=ACCENT_CYAN,
            fg="#000000",
            activebackground="#38bdf8",
            padx=12,
            pady=4,
            relief=tk.FLAT,
            command=self._on_register_click
        )
        self.connect_btn.pack(side=tk.RIGHT)

        # Camera Status Card
        self._create_card_header(main_frame, "CAMERA SUBSYSTEM")
        self.cam_card = tk.Frame(main_frame, bg=BG_CARD, padx=16, pady=14, highlightbackground=BG_CARD_LIGHT, highlightthickness=1)
        self.cam_card.pack(fill=tk.X, pady=(0, 14))

        self.cam_status_badge = tk.Label(
            self.cam_card,
            text="● CAMERA: NOT ACTIVE",
            font=("Helvetica", 11, "bold"),
            fg=TEXT_MUTED,
            bg=BG_CARD
        )
        self.cam_status_badge.pack(anchor=tk.W)

        self.cam_details_label = tk.Label(
            self.cam_card,
            text="Camera access requires explicit authorization for each session.\nNo background recording occurs.",
            font=("Helvetica", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD,
            justify=tk.LEFT
        )
        self.cam_details_label.pack(anchor=tk.W, pady=(6, 6))

        # Stop Camera Button (Visible when camera is active)
        self.stop_cam_btn = tk.Button(
            self.cam_card,
            text="🛑 STOP CAMERA STREAM",
            font=("Helvetica", 10, "bold"),
            bg=ACCENT_RED,
            fg=TEXT_WHITE,
            activebackground="#dc2626",
            padx=16,
            pady=6,
            relief=tk.FLAT,
            command=self._on_stop_click
        )

        # Web & VPN Shield Status Card
        self._create_card_header(main_frame, "NETWORK DEFENSE & WEB SHIELD")
        self.shield_card = tk.Frame(main_frame, bg=BG_CARD, padx=16, pady=12, highlightbackground=BG_CARD_LIGHT, highlightthickness=1)
        self.shield_card.pack(fill=tk.X, pady=(0, 14))

        self.shield_status_badge = tk.Label(
            self.shield_card,
            text="● WEB SHIELD: ACTIVE",
            font=("Helvetica", 10, "bold"),
            fg=ACCENT_GREEN,
            bg=BG_CARD
        )
        self.shield_status_badge.pack(anchor=tk.W)

        self.shield_details_label = tk.Label(
            self.shield_card,
            text="Enforcing network policy | Anti-VPN protection: ENABLED",
            font=("Helvetica", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD,
            justify=tk.LEFT
        )
        self.shield_details_label.pack(anchor=tk.W, pady=(4, 0))

        # Bottom Bar: Privacy & Info
        bottom_frame = tk.Frame(self.root, bg=BG_CARD, padx=20, pady=10)
        bottom_frame.pack(fill=tk.X, side=tk.BOTTOM)

        privacy_btn = tk.Button(
            bottom_frame,
            text="🛡️ Privacy & Consent Policy",
            font=("Helvetica", 8, "underline"),
            fg=ACCENT_CYAN,
            bg=BG_CARD,
            bd=0,
            cursor="hand2",
            command=self.on_privacy_click
        )
        privacy_btn.pack(side=tk.LEFT)

        footer_text = tk.Label(
            bottom_frame,
            text="NETSENTRY v1.0.0 • George Asiedu Annan • Neolifeporium",
            font=("Helvetica", 8),
            fg=TEXT_MUTED,
            bg=BG_CARD
        )
        footer_text.pack(side=tk.RIGHT)

    def _create_card_header(self, parent, text: str):
        lbl = tk.Label(
            parent,
            text=text,
            font=("Helvetica", 8, "bold"),
            fg=ACCENT_CYAN,
            bg=BG_DARK
        )
        lbl.pack(anchor=tk.W, pady=(0, 4))

    def _create_info_row(self, parent, label: str, value: str):
        row = tk.Frame(parent, bg=BG_CARD)
        row.pack(fill=tk.X, pady=2)
        tk.Label(row, text=label, font=("Helvetica", 9, "bold"), fg=TEXT_MUTED, bg=BG_CARD, width=12, anchor=tk.W).pack(side=tk.LEFT)
        tk.Label(row, text=value, font=("Consolas", 9), fg=TEXT_WHITE, bg=BG_CARD).pack(side=tk.LEFT)

    def set_connection_status(self, connected: bool, message: str = ""):
        """Update client connection status badge."""
        if connected:
            self.status_badge.config(text=f"● CONNECTED ({message})", fg=ACCENT_GREEN)
            self.connect_btn.config(text="Re-register", bg=BG_CARD_LIGHT, fg=TEXT_WHITE)
        else:
            self.status_badge.config(text="● NOT CONNECTED", fg=ACCENT_RED)
            self.connect_btn.config(text="Register & Connect", bg=ACCENT_CYAN, fg="#000000")

    def _on_register_click(self):
        url = self.server_url_entry.get().strip()
        code = self.reg_code_entry.get().strip()
        if not code or code == "NET-XXXX-XXX":
            messagebox.showwarning("Registration Code Required", "Please enter the registration code generated by your NETSENTRY administrator.")
            return
        self.on_register(url, code)

    def show_permission_prompt(self, session_uuid: str, admin_name: str, purpose: str, duration_minutes: int):
        """
        MANDATORY CONSENT PROMPT:
        Pops up an unmissable modal dialog asking user to explicitly ALLOW or DENY.
        """
        # Ensure window is visible and raised
        self.root.deiconify()
        self.root.lift()
        self.root.attributes("-topmost", True)

        dialog = tk.Toplevel(self.root)
        dialog.title("NETSENTRY - Camera Access Request")
        dialog.geometry("460x420")
        dialog.resizable(False, False)
        dialog.configure(bg=BG_DARK)
        dialog.transient(self.root)
        dialog.grab_set()

        # Center on parent
        x = self.root.winfo_x() + 30
        y = self.root.winfo_y() + 50
        dialog.geometry(f"+{x}+{y}")

        # Top Warning Banner
        warn_banner = tk.Frame(dialog, bg=BG_CARD, padx=16, pady=12)
        warn_banner.pack(fill=tk.X)

        tk.Label(
            warn_banner,
            text="⚠️  CAMERA ACCESS REQUEST",
            font=("Helvetica", 12, "bold"),
            fg=ACCENT_AMBER,
            bg=BG_CARD
        ).pack(anchor=tk.W)

        tk.Label(
            warn_banner,
            text="An administrator is requesting temporary camera access.",
            font=("Helvetica", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD
        ).pack(anchor=tk.W, pady=(2, 0))

        content_frame = tk.Frame(dialog, bg=BG_DARK, padx=20, pady=16)
        content_frame.pack(fill=tk.BOTH, expand=True)

        card = tk.Frame(content_frame, bg=BG_CARD, padx=16, pady=12, highlightbackground=BG_CARD_LIGHT, highlightthickness=1)
        card.pack(fill=tk.X, pady=(0, 14))

        self._create_info_row(card, "Administrator:", admin_name)
        self._create_info_row(card, "Target Device:", self.hostname)
        self._create_info_row(card, "Purpose:", purpose)
        self._create_info_row(card, "Max Duration:", f"{duration_minutes} minutes")

        notice_lbl = tk.Label(
            content_frame,
            text="Important Notice:\nCamera access cannot start without your explicit consent.\nIf you click ALLOW, a visible 'CAMERA ACTIVE' banner and a [STOP CAMERA] button will remain on your screen.",
            font=("Helvetica", 8),
            fg=TEXT_MUTED,
            bg=BG_DARK,
            justify=tk.LEFT
        )
        notice_lbl.pack(anchor=tk.W, pady=(0, 16))

        btn_frame = tk.Frame(content_frame, bg=BG_DARK)
        btn_frame.pack(fill=tk.X)

        def on_allow():
            dialog.destroy()
            self.root.attributes("-topmost", False)
            self.on_permission_response(session_uuid, True)

        def on_deny():
            dialog.destroy()
            self.root.attributes("-topmost", False)
            self.on_permission_response(session_uuid, False)

        deny_btn = tk.Button(
            btn_frame,
            text="🚫  DENY ACCESS",
            font=("Helvetica", 10, "bold"),
            bg="#334155",
            fg=TEXT_WHITE,
            activebackground="#475569",
            padx=16,
            pady=8,
            relief=tk.FLAT,
            command=on_deny
        )
        deny_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 8))

        allow_btn = tk.Button(
            btn_frame,
            text="✓  ALLOW ACCESS",
            font=("Helvetica", 10, "bold"),
            bg=ACCENT_GREEN,
            fg="#000000",
            activebackground="#34d399",
            padx=16,
            pady=8,
            relief=tk.FLAT,
            command=on_allow
        )
        allow_btn.pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=(8, 0))

    def set_camera_active(self, session_uuid: str, admin_name: str, duration_seconds: int):
        """Show visible 'CAMERA ACTIVE' banner with countdown and [STOP CAMERA] button."""
        self.active_session_uuid = session_uuid
        self.remaining_seconds = duration_seconds
        self._timer_running = True

        self.cam_status_badge.config(
            text="🔴  CAMERA ACTIVE - STREAMING LIVE",
            fg=ACCENT_RED
        )
        self.cam_card.config(highlightbackground=ACCENT_RED)

        self._update_cam_details(admin_name)
        self.stop_cam_btn.pack(anchor=tk.W, pady=(8, 0))

        # Start countdown thread
        threading.Thread(target=self._countdown_loop, args=(admin_name,), daemon=True).start()

    def set_camera_inactive(self, reason: str = ""):
        """Reset camera status to inactive."""
        self._timer_running = False
        self.active_session_uuid = None
        self.stop_cam_btn.pack_forget()

        self.cam_status_badge.config(
            text="●  CAMERA: NOT ACTIVE",
            fg=TEXT_MUTED
        )
        self.cam_card.config(highlightbackground=BG_CARD_LIGHT)
        msg = "Camera access requires explicit authorization for each session.\nNo background recording occurs."
        if reason:
            msg = f"Last session ended: {reason}\n" + msg
        self.cam_details_label.config(text=msg)

    def _update_cam_details(self, admin_name: str):
        mins = self.remaining_seconds // 60
        secs = self.remaining_seconds % 60
        time_str = f"{mins:02d}:{secs:02d}"

        self.cam_details_label.config(
            text=f"Session: {self.active_session_uuid[:8]}...\nRequested by: {admin_name}\nTime Remaining: {time_str}"
        )

    def _countdown_loop(self, admin_name: str):
        while self._timer_running and self.remaining_seconds > 0:
            time.sleep(1.0)
            self.remaining_seconds -= 1
            if self._timer_running:
                self.root.after(0, self._update_cam_details, admin_name)

        if self._timer_running and self.remaining_seconds <= 0:
            self.root.after(0, self.set_camera_inactive, "Session Expired (Maximum Duration Reached)")

    def _on_stop_click(self):
        if self.active_session_uuid:
            self.on_stop_camera(self.active_session_uuid)
            self.set_camera_inactive("Stopped by User")

    def show_privacy_dialog(self):
        """Displays NETSENTRY privacy policy and security guarantees."""
        win = tk.Toplevel(self.root)
        win.title("NETSENTRY - Security & Privacy Policy")
        win.geometry("480x420")
        win.configure(bg=BG_DARK)
        win.transient(self.root)

        tk.Label(
            win,
            text="NETSENTRY PRIVACY & SECURITY MODEL",
            font=("Helvetica", 11, "bold"),
            fg=ACCENT_CYAN,
            bg=BG_DARK
        ).pack(anchor=tk.W, padx=20, pady=(16, 8))

        text_box = tk.Text(win, bg=BG_CARD, fg=TEXT_WHITE, font=("Helvetica", 9), padx=12, pady=12, wrap=tk.WORD)
        text_box.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 16))

        policy = (
            "⚠️ STRICT ZERO-TOLERANCE ANTI-HACKING & ANTI-SCAM NOTICE:\n"
            "NETSENTRY is strictly engineered for authorized research, educational laboratories, and institutional IT defense. "
            "It is STRICTLY PROHIBITED to deploy this software for unauthorized surveillance, extortion, phishing, tech-support scams, "
            "or hacking. Any attempt to modify code to bypass explicit consent violates international cybercrime laws.\n\n"
            "1. LOCAL NETWORK DISCOVERY:\n"
            "NETSENTRY discovers devices on your local authorized Wi-Fi/LAN via standard ARP queries. "
            "It collects IP address, MAC address, hostname, and manufacturer to maintain device inventory.\n\n"
            "2. CONSENT-DRIVEN CAMERA ACCESS:\n"
            "Camera functionality CANNOT operate silently or in the background. Camera activation occurs ONLY when:\n"
            "  • You have enrolled this client with the administrator's registration code.\n"
            "  • An administrator actively requests camera access.\n"
            "  • A visible permission dialog appears on your screen.\n"
            "  • You explicitly click ALLOW.\n\n"
            "3. USER CONTROL & TERMINATION:\n"
            "While the camera is active, a prominent red 'CAMERA ACTIVE' banner and a [STOP CAMERA] button remain on your screen. "
            "You can terminate the stream at any second.\n\n"
            "4. NO COVERT SURVEILLANCE:\n"
            "There are NO features for silent activation, credential theft, OS bypasses, or stealth persistence. "
            "All sessions automatically expire after 10 minutes.\n\n"
            "5. NO FOOTAGE STORAGE:\n"
            "By default, video streams are relayed live to the authorized administrator and are NOT stored."
        )
        text_box.insert(tk.END, policy)
        text_box.config(state=tk.DISABLED)

    def set_web_shield_status(self, rules_count: int, vpn_blocked: bool, blocked_count: int = 0):
        """Update Web Defense Shield badge and details."""
        def _update():
            vpn_text = "Anti-VPN: ACTIVE" if vpn_blocked else "Anti-VPN: Permitted"
            self.shield_status_badge.config(
                text=f"● WEB SHIELD: ENFORCING ({rules_count} Rules)",
                fg=ACCENT_GREEN
            )
            self.shield_details_label.config(
                text=f"{vpn_text} | Blocked Violations: {blocked_count}"
            )
        self.root.after(0, _update)

    def run(self):
        self.root.mainloop()
