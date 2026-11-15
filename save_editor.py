#!/usr/bin/env python3

import os
import json
import base64
import shutil
import sqlite3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from py3rijndael import RijndaelCbc, Pkcs7Padding

try:
    import sqlcipher3
except ImportError:
    sqlcipher3 = None

DEFAULT_PASSWORD = "levelup321"

# "Wallet" table — actually stores CHARACTER LEVEL and XP per currency type
LEVEL_TABLE      = "tb_13c52bbaa8"   # called WALLET_TABLE in devirt, but stores level/xp
LEVEL_TYPE_COL   = "c_d79538c3b8"   # currency type (0=main character row)
LEVEL_FLAG_COL   = "c_9398111a4b"   # row flag (1 = main row for type 0)
CHAR_XP_COL      = "c_8ef3c1757a"   # character total XP (1200 in test save)
CHAR_LEVEL_COL   = "c_e3aa3bf474"   # character level (3 = Lv.3 in-game)

PROFILE_TABLE    = "tb_b58cac293e"
PROFILE_NAME     = "Name"           # only un-obfuscated column!

ACCOUNT_TABLE    = "tb_8f2a03f152"
ACCOUNT_LVL_COL  = "c_ce4fcf832f"   # account level (8)
ACCOUNT_XP_COL   = "c_b66e208cb4"   # account XP (261146318)

# Monarch table — stores GOLD and monarch XP
MONARCH_TABLE    = "tb_e973c32e29"
GOLD_COL         = "c_d1f333420b"   # actual in-game gold (6000)
MONARCH_XP_COL   = "c_af532e64a3"   # monarch XP (0)

# Stat table — character stat points
STAT_TABLE       = "tb_957a223c9b"
STAT_POINTS_COL  = "c_c982c144a0"   # unspent stat points (20)
STAT_STR_COL     = "c_7e92e023a5"   # strength (8)
STAT_VIT_COL     = "c_1c77e26632"   # vitality (3)
STAT_AGI_COL     = "c_b91b1c4561"   # agility (24)
STAT_INT_COL     = "c_3cd914b873"   # intelligence (5)
STAT_PER_COL     = "c_795582f14f"   # perception (14)

# Item/material table
ITEM_TABLE       = "tb_d40f87183c"
ITEM_ID_COL      = "c_4ec2cde1a1"   # item ID (e.g. 19900004)
ITEM_QTY_COL     = "c_8eb30bb564"   # quantity (e.g. 250)

PLATFORM_TABLE  = "tb_669f5dfe5a"
PLATFORM_MKT    = "c_995c6c7957"   # "steam" / "psn" etc.
PLATFORM_JSON   = "c_54693c0b17"   # full device JSON
PLATFORM_DEV_ID = "c_be336620f0"   # device key
PLATFORM_LANG   = "c_f9538cb1ab"   # language
PLATFORM_TZ     = "c_f0167fa7d2"   # timezone
PLATFORM_REGION = "c_4e168955ee"   # region code
PLATFORM_COUNTRY= "c_a078ff4547"   # country code

PLATFORM2_TABLE = "tb_4acea8d93f"
PLATFORM2_MKT   = "c_995c6c7957"   # "steam" / "psn" etc.

# CURRENCY_TYPE enum
CURRENCY_TYPES = {
    0: "Diamond (Paid)", 1: "Diamond (Free)", 2: "Gold", 3: "AP",
    4: "Guild Point", 5: "Friend Point", 6: "Player Exp", 7: "Shadow Exp",
    8: "Gate Tickets", 9: "Account Exp", 10: "Diamond (Combined)",
    11: "Indun Tickets", 12: "Raid Tickets", 13: "Advent Tickets",
    14: "Magic Essence", 15: "Gate Mileage", 16: "Shadow Soldier",
    17: "Unlimited Sweep", 18: "Hunter Story Key", 19: "Paid Magic Essence",
    20: "Magic Essence (Combined)", 21: "Chaos Tickets",
    22: "Dimension Gate Tickets", 23: "Skill Point", 24: "Weapon Point",
    25: "Special Point", 26: "Identity Point", 27: "Monarch Coin",
    28: "World Boss Tickets",
}

MIGRATION_KEYS = {}  # populated after derive_passphrase is defined


# ──────────────────── Crypto Helpers ────────────────────

def make_cipher(password: str) -> RijndaelCbc:
    raw = password.encode("utf-8")
    if len(raw) > 32:
        raise ValueError(f"Password too long ({len(raw)} bytes, max 32)")
    key = raw.ljust(32, b"\x00")
    return RijndaelCbc(key=key, iv=key, padding=Pkcs7Padding(32), block_size=32)


def derive_passphrase(steam_id: str, password: str) -> str:
    ct = make_cipher(password).encrypt(steam_id.encode("utf-8"))
    return base64.b64encode(ct).decode()


MIGRATION_KEYS = {
    "legacy_1234": "1234",
    "encrypt_DefaultUser": derive_passphrase("DefaultUser", DEFAULT_PASSWORD),
    "encrypt_0": derive_passphrase("0", DEFAULT_PASSWORD),
    "encrypt_empty": derive_passphrase("", DEFAULT_PASSWORD),
    "encrypt_levelup321": derive_passphrase("levelup321", DEFAULT_PASSWORD),
}


# ──────────────────── DB Operations ────────────────────

def open_encrypted_db(path: str, passphrase: str):
    """Open an encrypted SQLCipher DB and return connection."""
    conn = sqlcipher3.connect(path)
    conn.execute(f"PRAGMA key='{passphrase}'")
    conn.execute("SELECT count(*) FROM sqlite_master")  # verify
    return conn


def decrypt_db(src: str, dst: str, passphrase: str) -> int:
    conn = open_encrypted_db(src, passphrase)
    conn.execute(f"ATTACH DATABASE '{dst}' AS plaintext KEY ''")
    conn.execute("SELECT sqlcipher_export('plaintext')")
    conn.execute("DETACH DATABASE plaintext")
    tables = conn.execute(
        "SELECT count(*) FROM sqlite_master WHERE type='table'"
    ).fetchone()[0]
    conn.close()
    return tables


def encrypt_db(src: str, dst: str, passphrase: str) -> int:
    if os.path.exists(dst):
        os.remove(dst)
    conn = sqlcipher3.connect(dst)
    conn.execute(f"PRAGMA key='{passphrase}'")
    conn.execute(f"ATTACH DATABASE '{src}' AS plain KEY ''")
    schemas = conn.execute(
        "SELECT type, name, sql FROM plain.sqlite_master WHERE sql IS NOT NULL "
        "ORDER BY CASE type WHEN 'table' THEN 1 WHEN 'view' THEN 2 "
        "WHEN 'index' THEN 3 WHEN 'trigger' THEN 4 ELSE 5 END"
    ).fetchall()
    for _, name, sql in schemas:
        if name == "sqlite_sequence":
            continue
        conn.execute(sql)
    tables = conn.execute(
        "SELECT name FROM plain.sqlite_master WHERE type='table' AND name != 'sqlite_sequence'"
    ).fetchall()
    for (tbl,) in tables:
        conn.execute(f'INSERT INTO main."{tbl}" SELECT * FROM plain."{tbl}"')
    try:
        conn.execute("INSERT INTO main.sqlite_sequence SELECT * FROM plain.sqlite_sequence")
    except Exception:
        pass
    conn.commit()
    conn.execute("DETACH DATABASE plain")
    count = conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
    conn.close()
    return count


def rekey_db(src: str, dst: str, old_pp: str, new_pp: str) -> int:
    if os.path.exists(dst):
        os.remove(dst)
    conn = open_encrypted_db(src, old_pp)
    conn.execute(f"ATTACH DATABASE '{dst}' AS rekey KEY '{new_pp}'")
    conn.execute("SELECT sqlcipher_export('rekey')")
    conn.execute("DETACH DATABASE rekey")
    tables = conn.execute(
        "SELECT count(*) FROM sqlite_master WHERE type='table'"
    ).fetchone()[0]
    conn.close()
    return tables


# ──────────────────── Save Data Reader/Writer ────────────────────

class SaveData:
    """Reads/writes game values from an open SQLite/SQLCipher connection."""

    def __init__(self, conn):
        self.conn = conn

    # ── Gold (monarch table) ──
    def get_gold(self) -> int:
        r = self.conn.execute(
            f"SELECT {GOLD_COL} FROM {MONARCH_TABLE} WHERE c_3536de9619=1"
        ).fetchone()
        return r[0] if r else 0

    def set_gold(self, amount: int):
        self.conn.execute(
            f"UPDATE {MONARCH_TABLE} SET {GOLD_COL}=? WHERE c_3536de9619=1",
            (amount,)
        )
        self.conn.commit()

    # ── Character Level & XP (level table, row type=0 flag=1) ──
    def get_char_level(self) -> int:
        r = self.conn.execute(
            f"SELECT {CHAR_LEVEL_COL} FROM {LEVEL_TABLE} "
            f"WHERE {LEVEL_TYPE_COL}=0 AND {LEVEL_FLAG_COL}=1"
        ).fetchone()
        return r[0] if r else 0

    def get_char_xp(self) -> int:
        r = self.conn.execute(
            f"SELECT {CHAR_XP_COL} FROM {LEVEL_TABLE} "
            f"WHERE {LEVEL_TYPE_COL}=0 AND {LEVEL_FLAG_COL}=1"
        ).fetchone()
        return r[0] if r else 0

    def set_char_level(self, level: int):
        self.conn.execute(
            f"UPDATE {LEVEL_TABLE} SET {CHAR_LEVEL_COL}=? "
            f"WHERE {LEVEL_TYPE_COL}=0 AND {LEVEL_FLAG_COL}=1",
            (level,)
        )
        self.conn.commit()

    def set_char_xp(self, xp: int):
        self.conn.execute(
            f"UPDATE {LEVEL_TABLE} SET {CHAR_XP_COL}=? "
            f"WHERE {LEVEL_TYPE_COL}=0 AND {LEVEL_FLAG_COL}=1",
            (xp,)
        )
        self.conn.commit()

    # ── Account Level ──
    def get_account_level(self) -> int:
        r = self.conn.execute(
            f"SELECT {ACCOUNT_LVL_COL} FROM {ACCOUNT_TABLE} WHERE c_3536de9619=1"
        ).fetchone()
        return r[0] if r else 0

    def get_account_xp(self) -> int:
        r = self.conn.execute(
            f"SELECT {ACCOUNT_XP_COL} FROM {ACCOUNT_TABLE} WHERE c_3536de9619=1"
        ).fetchone()
        return r[0] if r else 0

    def set_account_level(self, level: int):
        self.conn.execute(
            f"UPDATE {ACCOUNT_TABLE} SET {ACCOUNT_LVL_COL}=? WHERE c_3536de9619=1",
            (level,)
        )
        self.conn.commit()

    def set_account_xp(self, xp: int):
        self.conn.execute(
            f"UPDATE {ACCOUNT_TABLE} SET {ACCOUNT_XP_COL}=? WHERE c_3536de9619=1",
            (xp,)
        )
        self.conn.commit()

    # ── Monarch XP ──
    def get_monarch_xp(self) -> int:
        r = self.conn.execute(
            f"SELECT {MONARCH_XP_COL} FROM {MONARCH_TABLE} WHERE c_3536de9619=1"
        ).fetchone()
        return r[0] if r else 0

    def set_monarch_xp(self, xp: int):
        self.conn.execute(
            f"UPDATE {MONARCH_TABLE} SET {MONARCH_XP_COL}=? WHERE c_3536de9619=1",
            (xp,)
        )
        self.conn.commit()

    # ── Stat Points ──
    def get_stats(self) -> dict:
        r = self.conn.execute(
            f"SELECT {STAT_POINTS_COL}, {STAT_STR_COL}, {STAT_VIT_COL}, "
            f"{STAT_AGI_COL}, {STAT_INT_COL}, {STAT_PER_COL} "
            f"FROM {STAT_TABLE} WHERE c_3536de9619=1"
        ).fetchone()
        if not r:
            return {}
        return {
            "stat_points": r[0], "strength": r[1], "vitality": r[2],
            "agility": r[3], "intelligence": r[4], "perception": r[5],
        }

    def set_stat(self, col: str, value: int):
        self.conn.execute(
            f"UPDATE {STAT_TABLE} SET {col}=? WHERE c_3536de9619=1", (value,)
        )
        self.conn.commit()

    # ── Items ──
    def get_items(self) -> list[tuple[int, int]]:
        rows = self.conn.execute(
            f"SELECT {ITEM_ID_COL}, {ITEM_QTY_COL} FROM {ITEM_TABLE}"
        ).fetchall()
        return rows

    def set_item_qty(self, item_id: int, qty: int):
        self.conn.execute(
            f"UPDATE {ITEM_TABLE} SET {ITEM_QTY_COL}=? WHERE {ITEM_ID_COL}=?",
            (qty, item_id)
        )
        self.conn.commit()

    # ── Profile ──
    def get_profile_name(self) -> str:
        r = self.conn.execute(
            f"SELECT {PROFILE_NAME} FROM {PROFILE_TABLE} WHERE c_3536de9619=1"
        ).fetchone()
        return r[0] if r else ""

    def set_profile_name(self, name: str):
        self.conn.execute(
            f"UPDATE {PROFILE_TABLE} SET {PROFILE_NAME}=? WHERE c_3536de9619=1",
            (name,)
        )
        self.conn.commit()

    # ── Platform Info ──
    def get_platform_info(self) -> dict:
        r = self.conn.execute(
            f"SELECT {PLATFORM_MKT}, {PLATFORM_JSON}, {PLATFORM_DEV_ID}, "
            f"{PLATFORM_LANG}, {PLATFORM_TZ}, {PLATFORM_REGION}, {PLATFORM_COUNTRY} "
            f"FROM {PLATFORM_TABLE} WHERE c_3536de9619=1"
        ).fetchone()
        if not r:
            return {}
        device_json = {}
        try:
            device_json = json.loads(r[1]) if r[1] else {}
        except Exception:
            pass
        return {
            "market": r[0], "device_json": device_json,
            "device_json_raw": r[1], "device_id": r[2],
            "language": r[3], "timezone": r[4],
            "region": r[5], "country": r[6],
        }

    def set_platform_market(self, market: str):
        self.conn.execute(
            f"UPDATE {PLATFORM_TABLE} SET {PLATFORM_MKT}=? WHERE c_3536de9619=1",
            (market,)
        )
        self.conn.execute(
            f"UPDATE {PLATFORM2_TABLE} SET {PLATFORM2_MKT}=?", (market,)
        )
        self.conn.commit()

    def set_platform_json(self, json_str: str):
        self.conn.execute(
            f"UPDATE {PLATFORM_TABLE} SET {PLATFORM_JSON}=? WHERE c_3536de9619=1",
            (json_str,)
        )
        self.conn.commit()


# ──────────────────── GUI ────────────────────

class SaveEditorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ByteOp — SL:ARISE Save Editor")
        self.resizable(False, False)
        self.configure(bg="#1e1e1e")
        self.conn = None
        self.save_data = None
        self.working_db = None  # path to temp decrypted copy
        self.original_path = None
        self.current_passphrase = None

        if sqlcipher3 is None:
            messagebox.showerror("Missing dependency",
                "sqlcipher3 not installed.\n\npip install sqlcipher3-binary")

        self._setup_style()
        self._build_ui()

    def _setup_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background="#1e1e1e", foreground="#e0e0e0",
                        fieldbackground="#2d2d2d", font=("Segoe UI", 10))
        style.configure("TLabel", background="#1e1e1e", foreground="#e0e0e0")
        style.configure("TButton", background="#3a3a3a", foreground="#e0e0e0",
                        padding=(10, 5))
        style.map("TButton",
                  background=[("active", "#505050")],
                  foreground=[("active", "#ffffff")])
        style.configure("Accent.TButton", background="#0078d4", foreground="#ffffff")
        style.map("Accent.TButton", background=[("active", "#1a8ad4")])
        style.configure("Warn.TButton", background="#d83b01", foreground="#ffffff")
        style.map("Warn.TButton", background=[("active", "#e8520a")])
        style.configure("TEntry", fieldbackground="#2d2d2d", foreground="#e0e0e0",
                        insertcolor="#e0e0e0")
        style.configure("TLabelframe", background="#1e1e1e", foreground="#808080")
        style.configure("TLabelframe.Label", background="#1e1e1e", foreground="#808080",
                        font=("Segoe UI", 9))
        style.configure("TNotebook", background="#1e1e1e")
        style.configure("TNotebook.Tab", background="#2d2d2d", foreground="#e0e0e0",
                        padding=(12, 4))
        style.map("TNotebook.Tab",
                  background=[("selected", "#0078d4")],
                  foreground=[("selected", "#ffffff")])
        style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"),
                        foreground="#ffffff")
        style.configure("Value.TLabel", font=("Segoe UI", 11),
                        foreground="#4ec9b0")
        style.configure("Treeview", background="#2d2d2d", foreground="#e0e0e0",
                        fieldbackground="#2d2d2d", font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background="#3a3a3a", foreground="#e0e0e0",
                        font=("Segoe UI", 9, "bold"))

    def _build_ui(self):
        pad = {"padx": 6, "pady": 3}

        # ── Top: Open / Settings ──
        frame_open = ttk.LabelFrame(self, text="Open Save", padding=8)
        frame_open.pack(fill="x", padx=10, pady=(10, 4))

        ttk.Label(frame_open, text="Steam/Platform ID:").grid(row=0, column=0, sticky="w", **pad)
        self.steam_id_var = tk.StringVar()
        ttk.Entry(frame_open, textvariable=self.steam_id_var, width=30).grid(
            row=0, column=1, sticky="ew", **pad)

        ttk.Label(frame_open, text="Password:").grid(row=0, column=2, sticky="w", **pad)
        self.password_var = tk.StringVar(value=DEFAULT_PASSWORD)
        ttk.Entry(frame_open, textvariable=self.password_var, width=16).grid(
            row=0, column=3, sticky="ew", **pad)

        ttk.Label(frame_open, text="Save File:").grid(row=1, column=0, sticky="w", **pad)
        self.file_var = tk.StringVar()
        ttk.Entry(frame_open, textvariable=self.file_var, width=50).grid(
            row=1, column=1, columnspan=3, sticky="ew", **pad)
        ttk.Button(frame_open, text="Browse…", command=self.on_browse).grid(
            row=1, column=4, **pad)

        btn_row = ttk.Frame(frame_open)
        btn_row.grid(row=2, column=0, columnspan=5, pady=(6, 0))
        ttk.Button(btn_row, text="🔓 Open & Decrypt", style="Accent.TButton",
                   command=self.on_open).pack(side="left", padx=6)
        ttk.Button(btn_row, text="💾 Save & Re-encrypt", style="Warn.TButton",
                   command=self.on_save).pack(side="left", padx=6)
        ttk.Button(btn_row, text="💾 Save and encrypt to every platform and users (PS5)", style="Warn.TButton",
                   command=self.on_save_migration).pack(side="left", padx=6)

        frame_open.columnconfigure(1, weight=1)

        # ── Notebook with tabs ──
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=4)

        # Tab 1: Character (Gold, Level, Stats)
        self.tab_character = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_character, text="  Character  ")
        self._build_character_tab()

        # Tab 2: Items
        self.tab_items = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_items, text="  Items  ")
        self._build_items_tab()

        # Tab 3: Profile & Account
        self.tab_profile = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_profile, text="  Profile & Account  ")
        self._build_profile_tab()

        # Tab 4: Platform Info
        self.tab_platform = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_platform, text="  Platform (PC/PS5)  ")
        self._build_platform_tab()

        # Tab 5: Raw Decrypt/Encrypt
        self.tab_raw = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_raw, text="  Raw Decrypt/Encrypt  ")
        self._build_raw_tab()

        # ── Status bar ──
        self.status_var = tk.StringVar(value="Ready — Open a save file to begin editing")
        ttk.Label(self, textvariable=self.status_var, foreground="#808080",
                  font=("Segoe UI", 9)).pack(fill="x", padx=12, pady=(2, 10))

    # ── Character Tab (Gold, Level, Stats) ──
    def _build_character_tab(self):
        f = self.tab_character

        # Gold (from monarch table)
        gf = ttk.LabelFrame(f, text="Gold (Monarch Table)", padding=8)
        gf.pack(fill="x", padx=8, pady=6)
        ttk.Label(gf, text="Gold:").grid(row=0, column=0, sticky="w", padx=4)
        self.gold_display = tk.StringVar(value="—")
        ttk.Label(gf, textvariable=self.gold_display, style="Value.TLabel").grid(
            row=0, column=1, sticky="w", padx=4)
        ttk.Label(gf, text="New:").grid(row=0, column=2, sticky="w", padx=(20, 4))
        self.gold_entry = tk.StringVar()
        ttk.Entry(gf, textvariable=self.gold_entry, width=14).grid(row=0, column=3, padx=4)
        ttk.Button(gf, text="Set", command=self.on_set_gold).grid(row=0, column=4, padx=4)

        ttk.Label(gf, text="Monarch XP:").grid(row=1, column=0, sticky="w", padx=4)
        self.monarch_xp_display = tk.StringVar(value="—")
        ttk.Label(gf, textvariable=self.monarch_xp_display, style="Value.TLabel").grid(
            row=1, column=1, sticky="w", padx=4)
        ttk.Label(gf, text="New:").grid(row=1, column=2, sticky="w", padx=(20, 4))
        self.monarch_xp_entry = tk.StringVar()
        ttk.Entry(gf, textvariable=self.monarch_xp_entry, width=14).grid(row=1, column=3, padx=4)
        ttk.Button(gf, text="Set", command=self.on_set_monarch_xp).grid(row=1, column=4, padx=4)

        # Character Level & XP (from level table, type=0, flag=1)
        lf = ttk.LabelFrame(f, text="Character Level & XP (Sung Jinwoo)", padding=8)
        lf.pack(fill="x", padx=8, pady=6)

        ttk.Label(lf, text="Level:").grid(row=0, column=0, sticky="w", padx=4)
        self.char_level_display = tk.StringVar(value="—")
        ttk.Label(lf, textvariable=self.char_level_display, style="Value.TLabel").grid(
            row=0, column=1, sticky="w", padx=4)
        ttk.Label(lf, text="New:").grid(row=0, column=2, sticky="w", padx=(20, 4))
        self.char_level_entry = tk.StringVar()
        ttk.Entry(lf, textvariable=self.char_level_entry, width=10).grid(row=0, column=3, padx=4)
        ttk.Button(lf, text="Set", command=self.on_set_char_level).grid(row=0, column=4, padx=4)

        ttk.Label(lf, text="Total XP:").grid(row=1, column=0, sticky="w", padx=4)
        self.char_xp_display = tk.StringVar(value="—")
        ttk.Label(lf, textvariable=self.char_xp_display, style="Value.TLabel").grid(
            row=1, column=1, sticky="w", padx=4)
        ttk.Label(lf, text="New:").grid(row=1, column=2, sticky="w", padx=(20, 4))
        self.char_xp_entry = tk.StringVar()
        ttk.Entry(lf, textvariable=self.char_xp_entry, width=14).grid(row=1, column=3, padx=4)
        ttk.Button(lf, text="Set", command=self.on_set_char_xp).grid(row=1, column=4, padx=4)

        # Stats
        sf = ttk.LabelFrame(f, text="Stat Points & Stats", padding=8)
        sf.pack(fill="x", padx=8, pady=6)

        self.stat_vars = {}  # key -> (display_var, entry_var)
        stat_defs = [
            ("stat_points", "Unspent Points", STAT_POINTS_COL),
            ("strength",    "Strength",       STAT_STR_COL),
            ("vitality",    "Vitality",       STAT_VIT_COL),
            ("agility",     "Agility",        STAT_AGI_COL),
            ("intelligence","Intelligence",   STAT_INT_COL),
            ("perception",  "Perception",     STAT_PER_COL),
        ]
        for i, (key, label, col) in enumerate(stat_defs):
            ttk.Label(sf, text=f"{label}:").grid(row=i, column=0, sticky="w", padx=4, pady=1)
            dvar = tk.StringVar(value="—")
            ttk.Label(sf, textvariable=dvar, style="Value.TLabel", width=8).grid(
                row=i, column=1, sticky="w", padx=4)
            ttk.Label(sf, text="New:").grid(row=i, column=2, sticky="w", padx=(12, 4))
            evar = tk.StringVar()
            ttk.Entry(sf, textvariable=evar, width=8).grid(row=i, column=3, padx=4)
            col_ref = col  # capture for lambda
            ttk.Button(sf, text="Set",
                       command=lambda c=col_ref, k=key: self.on_set_stat(c, k)).grid(
                row=i, column=4, padx=4)
            self.stat_vars[key] = (dvar, evar)

    # ── Items Tab ──
    def _build_items_tab(self):
        f = self.tab_items

        ttk.Label(f, text="Items / Materials — click a row to edit quantity:",
                  font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=12, pady=(8, 2))
        tree_frame = ttk.Frame(f)
        tree_frame.pack(fill="both", expand=True, padx=8, pady=4)
        cols = ("item_id", "quantity")
        self.item_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=12)
        self.item_tree.heading("item_id", text="Item ID")
        self.item_tree.heading("quantity", text="Quantity")
        self.item_tree.column("item_id", width=160, anchor="center")
        self.item_tree.column("quantity", width=120, anchor="e")
        sb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.item_tree.yview)
        self.item_tree.configure(yscrollcommand=sb.set)
        self.item_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.item_tree.bind("<<TreeviewSelect>>", self._on_item_select)

        ef = ttk.LabelFrame(f, text="Edit Selected Item", padding=6)
        ef.pack(fill="x", padx=8, pady=4)
        ttk.Label(ef, text="Selected:").grid(row=0, column=0, padx=4)
        self.edit_item_label = tk.StringVar(value="(click a row above)")
        ttk.Label(ef, textvariable=self.edit_item_label, style="Value.TLabel").grid(
            row=0, column=1, sticky="w", padx=4)
        ttk.Label(ef, text="New Qty:").grid(row=0, column=2, padx=(16, 4))
        self.edit_item_qty_var = tk.StringVar()
        ttk.Entry(ef, textvariable=self.edit_item_qty_var, width=14).grid(row=0, column=3, padx=4)
        ttk.Button(ef, text="Apply", command=self.on_apply_item_edit).grid(row=0, column=4, padx=4)

        self._sel_item_id = None

        ttk.Label(f, text="Known items: 19900004=Silver Coins, 19900001=Keys",
                  foreground="#808080", font=("Segoe UI", 8)).pack(anchor="w", padx=12, pady=2)

    def _on_item_select(self, event):
        sel = self.item_tree.selection()
        if not sel:
            return
        vals = self.item_tree.item(sel[0], "values")
        self._sel_item_id = int(vals[0])
        self.edit_item_label.set(f"Item {vals[0]}")
        self.edit_item_qty_var.set(str(vals[1]).replace(",", ""))

    # ── Profile & Account Tab ──
    def _build_profile_tab(self):
        f = self.tab_profile

        pf = ttk.LabelFrame(f, text="Profile", padding=8)
        pf.pack(fill="x", padx=8, pady=6)

        ttk.Label(pf, text="Name:").grid(row=0, column=0, sticky="w", padx=4)
        self.name_display = tk.StringVar(value="—")
        ttk.Label(pf, textvariable=self.name_display, style="Value.TLabel").grid(
            row=0, column=1, sticky="w", padx=4)
        ttk.Label(pf, text="New:").grid(row=0, column=2, sticky="w", padx=(20, 4))
        self.name_entry = tk.StringVar()
        ttk.Entry(pf, textvariable=self.name_entry, width=20).grid(row=0, column=3, padx=4)
        ttk.Button(pf, text="Set", command=self.on_set_name).grid(row=0, column=4, padx=4)

        lf = ttk.LabelFrame(f, text="Account Level & XP", padding=8)
        lf.pack(fill="x", padx=8, pady=6)

        ttk.Label(lf, text="Account Level:").grid(row=0, column=0, sticky="w", padx=4)
        self.acct_level_display = tk.StringVar(value="—")
        ttk.Label(lf, textvariable=self.acct_level_display, style="Value.TLabel").grid(
            row=0, column=1, sticky="w", padx=4)
        ttk.Label(lf, text="New:").grid(row=0, column=2, sticky="w", padx=(20, 4))
        self.acct_level_entry = tk.StringVar()
        ttk.Entry(lf, textvariable=self.acct_level_entry, width=10).grid(row=0, column=3, padx=4)
        ttk.Button(lf, text="Set", command=self.on_set_acct_level).grid(row=0, column=4, padx=4)

        ttk.Label(lf, text="Account XP:").grid(row=1, column=0, sticky="w", padx=4)
        self.acct_xp_display = tk.StringVar(value="—")
        ttk.Label(lf, textvariable=self.acct_xp_display, style="Value.TLabel").grid(
            row=1, column=1, sticky="w", padx=4)
        ttk.Label(lf, text="New:").grid(row=1, column=2, sticky="w", padx=(20, 4))
        self.acct_xp_entry = tk.StringVar()
        ttk.Entry(lf, textvariable=self.acct_xp_entry, width=14).grid(row=1, column=3, padx=4)
        ttk.Button(lf, text="Set", command=self.on_set_acct_xp).grid(row=1, column=4, padx=4)

    # ── Platform Tab ──
    def _build_platform_tab(self):
        f = self.tab_platform

        ttk.Label(f, text="Platform-Specific Fields (PC → PS5 Transfer Analysis)",
                  style="Header.TLabel").pack(anchor="w", padx=8, pady=(8, 4))
        ttk.Label(f, text=(
            "These fields identify the save as belonging to a specific platform.\n"
            "For PS5 import, you may need to change 'steam' → 'psn' and update device info."
        ), foreground="#808080", font=("Segoe UI", 9)).pack(anchor="w", padx=8)

        pf = ttk.LabelFrame(f, text="Platform Fields", padding=8)
        pf.pack(fill="x", padx=8, pady=6)

        labels = [
            ("Market:", "platform_market"),
            ("Device ID:", "platform_devid"),
            ("Language:", "platform_lang"),
            ("Timezone:", "platform_tz"),
            ("Region:", "platform_region"),
            ("Country:", "platform_country"),
        ]
        self.platform_vars = {}
        for i, (label, key) in enumerate(labels):
            ttk.Label(pf, text=label).grid(row=i, column=0, sticky="w", padx=4, pady=2)
            var = tk.StringVar(value="—")
            self.platform_vars[key] = var
            ttk.Label(pf, textvariable=var, style="Value.TLabel").grid(
                row=i, column=1, sticky="w", padx=4, pady=2)

        # Device JSON
        jf = ttk.LabelFrame(f, text="Device Info JSON", padding=8)
        jf.pack(fill="both", expand=True, padx=8, pady=6)
        self.device_json_text = tk.Text(jf, height=8, bg="#2d2d2d", fg="#e0e0e0",
                                         insertbackground="#e0e0e0", font=("Consolas", 9),
                                         wrap="word")
        self.device_json_text.pack(fill="both", expand=True)

        # Platform edit buttons
        bf = ttk.Frame(f)
        bf.pack(fill="x", padx=8, pady=4)
        ttk.Button(bf, text="Set Market to 'psn'",
                   command=lambda: self.on_set_market("psn")).pack(side="left", padx=4)
        ttk.Button(bf, text="Set Market to 'steam'",
                   command=lambda: self.on_set_market("steam")).pack(side="left", padx=4)
        ttk.Button(bf, text="Save Device JSON Edits",
                   command=self.on_save_device_json).pack(side="right", padx=4)

    # ── Raw Tab ──
    def _build_raw_tab(self):
        f = self.tab_raw

        # Passphrase display
        ppf = ttk.LabelFrame(f, text="Passphrase", padding=8)
        ppf.pack(fill="x", padx=8, pady=6)
        self.passphrase_var = tk.StringVar()
        ttk.Entry(ppf, textvariable=self.passphrase_var, state="readonly", width=50).pack(
            side="left", fill="x", expand=True, padx=4)
        ttk.Button(ppf, text="Derive", command=self.on_derive).pack(side="left", padx=4)
        ttk.Button(ppf, text="Copy", command=self.on_copy_pp).pack(side="left", padx=4)

        # Standalone decrypt/encrypt
        df = ttk.LabelFrame(f, text="Standalone Decrypt / Encrypt", padding=8)
        df.pack(fill="x", padx=8, pady=6)
        ttk.Button(df, text="Decrypt .db → plain SQLite", style="Accent.TButton",
                   command=self.on_decrypt_standalone).pack(side="left", padx=8, pady=4)
        ttk.Button(df, text="Encrypt SQLite → .db", style="Accent.TButton",
                   command=self.on_encrypt_standalone).pack(side="left", padx=8, pady=4)

        # Migration re-encrypt
        mf = ttk.LabelFrame(f, text="Re-encrypt with Migration Key", padding=8)
        mf.pack(fill="x", padx=8, pady=6)
        ttk.Label(mf, text="Target key:").pack(side="left", padx=4)
        self.mig_key_var = tk.StringVar(value="legacy_1234")
        ttk.Combobox(mf, textvariable=self.mig_key_var,
                     values=list(MIGRATION_KEYS.keys()),
                     state="readonly", width=24).pack(side="left", padx=4)
        ttk.Button(mf, text="Re-encrypt", style="Accent.TButton",
                   command=self.on_rekey).pack(side="left", padx=8)
        ttk.Label(mf, text=(
            "Game's migration system auto-rekeys to\n"
            "current user's platform key on first load."
        ), foreground="#808080", font=("Segoe UI", 8)).pack(side="left", padx=8)

    # ──────────────────── Actions ────────────────────

    def _get_passphrase(self) -> str | None:
        pp = self.passphrase_var.get()
        if pp:
            return pp
        sid = self.steam_id_var.get().strip()
        pw = self.password_var.get()
        if not sid:
            messagebox.showwarning("Missing", "Enter a Steam/Platform ID.")
            return None
        pp = derive_passphrase(sid, pw)
        self.passphrase_var.set(pp)
        return pp

    def on_browse(self):
        path = filedialog.askopenfilename(
            title="Select save database",
            filetypes=[("Database files", "*.db *.sqlite *.sqlite3"),
                       ("SaveData", "SaveData*"),
                       ("All files", "*.*")])
        if path:
            self.file_var.set(path)

    def on_derive(self):
        sid = self.steam_id_var.get().strip()
        pw = self.password_var.get()
        if not sid:
            messagebox.showwarning("Missing", "Enter a Steam/Platform ID.")
            return
        try:
            pp = derive_passphrase(sid, pw)
            self.passphrase_var.set(pp)
            self.status_var.set(f"Passphrase derived for {sid}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_copy_pp(self):
        pp = self.passphrase_var.get()
        if pp:
            self.clipboard_clear()
            self.clipboard_append(pp)
            self.status_var.set("Passphrase copied")

    def on_open(self):
        """Open and decrypt save, load into editor."""
        inpath = self.file_var.get().strip()
        if not inpath or not os.path.isfile(inpath):
            messagebox.showwarning("Missing", "Select a valid save file.")
            return
        pp = self._get_passphrase()
        if not pp:
            return

        try:
            # Close existing connection
            if self.conn:
                self.conn.close()

            # Decrypt to temp file
            self.original_path = inpath
            self.current_passphrase = pp
            tmpdir = os.path.join(os.path.dirname(inpath), ".byteop_tmp")
            os.makedirs(tmpdir, exist_ok=True)
            self.working_db = os.path.join(tmpdir, "working.db")
            if os.path.exists(self.working_db):
                os.remove(self.working_db)

            tables = decrypt_db(inpath, self.working_db, pp)

            # Open plain SQLite
            self.conn = sqlite3.connect(self.working_db)
            self.save_data = SaveData(self.conn)

            self._refresh_all()
            self.status_var.set(
                f"Opened: {os.path.basename(inpath)} — {tables} tables — editing live")
        except Exception as e:
            messagebox.showerror("Open failed", str(e))

    def _refresh_all(self):
        """Refresh all displayed values from DB."""
        if not self.save_data:
            return

        # Character tab: Gold, Level, Stats
        self.gold_display.set(f"{self.save_data.get_gold():,}")
        self.monarch_xp_display.set(f"{self.save_data.get_monarch_xp():,}")
        self.char_level_display.set(str(self.save_data.get_char_level()))
        self.char_xp_display.set(f"{self.save_data.get_char_xp():,}")

        stats = self.save_data.get_stats()
        for key, (dvar, _) in self.stat_vars.items():
            dvar.set(str(stats.get(key, 0)))

        # Items tab
        for item in self.item_tree.get_children():
            self.item_tree.delete(item)
        for item_id, qty in self.save_data.get_items():
            self.item_tree.insert("", "end", values=(item_id, f"{qty:,}"))

        # Profile tab
        self.name_display.set(self.save_data.get_profile_name())
        self.acct_level_display.set(str(self.save_data.get_account_level()))
        self.acct_xp_display.set(f"{self.save_data.get_account_xp():,}")

        # Platform
        info = self.save_data.get_platform_info()
        if info:
            self.platform_vars["platform_market"].set(info.get("market", "—"))
            self.platform_vars["platform_devid"].set(info.get("device_id", "—"))
            self.platform_vars["platform_lang"].set(info.get("language", "—"))
            self.platform_vars["platform_tz"].set(info.get("timezone", "—"))
            self.platform_vars["platform_region"].set(info.get("region", "—"))
            self.platform_vars["platform_country"].set(info.get("country", "—"))

            self.device_json_text.delete("1.0", "end")
            try:
                pretty = json.dumps(info.get("device_json", {}), indent=2, ensure_ascii=False)
            except Exception:
                pretty = info.get("device_json_raw", "")
            self.device_json_text.insert("1.0", pretty)

    def on_save(self):
        """Re-encrypt working DB back with original passphrase."""
        if not self.working_db or not self.original_path:
            messagebox.showwarning("Nothing open", "Open a save first.")
            return

        outpath = filedialog.asksaveasfilename(
            title="Save re-encrypted database",
            initialdir=os.path.dirname(self.original_path),
            initialfile=os.path.basename(self.original_path),
            filetypes=[("Database files", "*.db"), ("All files", "*.*")])
        if not outpath:
            return

        try:
            self.conn.commit()
            tables = encrypt_db(self.working_db, outpath, self.current_passphrase)
            sz = os.path.getsize(outpath)
            self.status_var.set(
                f"Saved: {tables} tables, {sz:,} bytes → {os.path.basename(outpath)}")
            messagebox.showinfo("Saved",
                f"Re-encrypted with original passphrase.\n\n"
                f"Tables: {tables}\nSize: {sz:,} bytes\n"
                f"File: {os.path.basename(outpath)}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def on_save_migration(self):
        """Re-encrypt with legacy_1234 for cross-platform migration."""
        if not self.working_db or not self.original_path:
            messagebox.showwarning("Nothing open", "Open a save first.")
            return

        base = os.path.basename(self.original_path)
        name, ext = os.path.splitext(base)
        outpath = filedialog.asksaveasfilename(
            title="Save with migration key (1234)",
            initialdir=os.path.dirname(self.original_path),
            initialfile=f"{name}_migration{ext or '.db'}",
            filetypes=[("Database files", "*.db"),
                       ("SaveData", "SaveData*"),
                       ("All files", "*.*")])
        if not outpath:
            return

        try:
            self.conn.commit()
            tables = encrypt_db(self.working_db, outpath, "1234")
            sz = os.path.getsize(outpath)
            self.status_var.set(
                f"Migration save: {tables} tables, {sz:,} bytes → {os.path.basename(outpath)}")
            messagebox.showinfo("Migration Save",
                f"Encrypted with migration key '1234'.\n\n"
                f"Tables: {tables}\nSize: {sz:,} bytes\n"
                f"File: {os.path.basename(outpath)}\n\n"
                f"The game's migration system will auto-rekey\n"
                f"to the current user's platform key on first load.\n\n"
                f"⚠ Back up your original save before replacing it!")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    # ── Editors ──

    def _require_open(self) -> bool:
        if not self.save_data:
            messagebox.showwarning("Not open", "Open a save file first.")
            return False
        return True

    def on_set_gold(self):
        if not self._require_open():
            return
        try:
            val = int(self.gold_entry.get().replace(",", "").strip())
            self.save_data.set_gold(val)
            self._refresh_all()
            self.status_var.set(f"Gold set to {val:,}")
        except ValueError:
            messagebox.showwarning("Invalid", "Enter a valid number.")

    def on_set_monarch_xp(self):
        if not self._require_open():
            return
        try:
            val = int(self.monarch_xp_entry.get().replace(",", "").strip())
            self.save_data.set_monarch_xp(val)
            self._refresh_all()
            self.status_var.set(f"Monarch XP set to {val:,}")
        except ValueError:
            messagebox.showwarning("Invalid", "Enter a valid number.")

    def on_set_char_level(self):
        if not self._require_open():
            return
        try:
            val = int(self.char_level_entry.get().strip())
            self.save_data.set_char_level(val)
            self._refresh_all()
            self.status_var.set(f"Character level set to {val}")
        except ValueError:
            messagebox.showwarning("Invalid", "Enter a valid number.")

    def on_set_char_xp(self):
        if not self._require_open():
            return
        try:
            val = int(self.char_xp_entry.get().replace(",", "").strip())
            self.save_data.set_char_xp(val)
            self._refresh_all()
            self.status_var.set(f"Character XP set to {val:,}")
        except ValueError:
            messagebox.showwarning("Invalid", "Enter a valid number.")

    def on_set_stat(self, col: str, key: str):
        if not self._require_open():
            return
        _, evar = self.stat_vars[key]
        try:
            val = int(evar.get().strip())
            self.save_data.set_stat(col, val)
            self._refresh_all()
            self.status_var.set(f"{key.replace('_', ' ').title()} set to {val}")
        except ValueError:
            messagebox.showwarning("Invalid", "Enter a valid number.")

    def on_apply_item_edit(self):
        if not self._require_open():
            return
        if self._sel_item_id is None:
            messagebox.showwarning("No selection", "Click a row in the item table first.")
            return
        try:
            val = int(self.edit_item_qty_var.get().replace(",", "").strip())
            self.save_data.set_item_qty(self._sel_item_id, val)
            self._refresh_all()
            self.status_var.set(f"Item {self._sel_item_id} quantity set to {val:,}")
        except ValueError:
            messagebox.showwarning("Invalid", "Enter a valid number.")

    def on_set_name(self):
        if not self._require_open():
            return
        name = self.name_entry.get().strip()
        if not name:
            messagebox.showwarning("Empty", "Enter a name.")
            return
        self.save_data.set_profile_name(name)
        self._refresh_all()
        self.status_var.set(f"Name set to '{name}'")

    def on_set_acct_level(self):
        if not self._require_open():
            return
        try:
            val = int(self.acct_level_entry.get().strip())
            self.save_data.set_account_level(val)
            self._refresh_all()
            self.status_var.set(f"Account level set to {val}")
        except ValueError:
            messagebox.showwarning("Invalid", "Enter a valid number.")

    def on_set_acct_xp(self):
        if not self._require_open():
            return
        try:
            val = int(self.acct_xp_entry.get().replace(",", "").strip())
            self.save_data.set_account_xp(val)
            self._refresh_all()
            self.status_var.set(f"Account XP set to {val:,}")
        except ValueError:
            messagebox.showwarning("Invalid", "Enter a valid number.")

    def on_set_market(self, market: str):
        if not self._require_open():
            return
        self.save_data.set_platform_market(market)
        self._refresh_all()
        self.status_var.set(f"Platform market set to '{market}'")

    def on_save_device_json(self):
        if not self._require_open():
            return
        text = self.device_json_text.get("1.0", "end").strip()
        try:
            json.loads(text)  # validate
        except json.JSONDecodeError as e:
            messagebox.showerror("Invalid JSON", f"Fix JSON syntax:\n{e}")
            return
        self.save_data.set_platform_json(text)
        self._refresh_all()
        self.status_var.set("Device JSON updated")

    # ── Standalone operations (Raw tab) ──

    def on_decrypt_standalone(self):
        inpath = self.file_var.get().strip()
        if not inpath or not os.path.isfile(inpath):
            messagebox.showwarning("Missing", "Select a .db file.")
            return
        pp = self._get_passphrase()
        if not pp:
            return
        name, _ = os.path.splitext(os.path.basename(inpath))
        outpath = filedialog.asksaveasfilename(
            title="Save decrypted SQLite",
            initialfile=name + "_decrypted.db",
            initialdir=os.path.dirname(inpath),
            filetypes=[("SQLite", "*.db"), ("All", "*.*")])
        if not outpath:
            return
        try:
            tables = decrypt_db(inpath, outpath, pp)
            sz = os.path.getsize(outpath)
            self.status_var.set(f"Decrypted: {tables} tables, {sz:,} bytes")
        except Exception as e:
            messagebox.showerror("Decrypt failed", str(e))

    def on_encrypt_standalone(self):
        inpath = self.file_var.get().strip()
        if not inpath or not os.path.isfile(inpath):
            messagebox.showwarning("Missing", "Select a plain SQLite file.")
            return
        pp = self._get_passphrase()
        if not pp:
            return
        name, _ = os.path.splitext(os.path.basename(inpath))
        if name.endswith("_decrypted"):
            name = name[:-10]
        outpath = filedialog.asksaveasfilename(
            title="Save encrypted .db",
            initialfile=name + ".db",
            initialdir=os.path.dirname(inpath),
            filetypes=[("SQLCipher", "*.db"), ("All", "*.*")])
        if not outpath:
            return
        try:
            tables = encrypt_db(inpath, outpath, pp)
            sz = os.path.getsize(outpath)
            self.status_var.set(f"Encrypted: {tables} tables, {sz:,} bytes")
        except Exception as e:
            messagebox.showerror("Encrypt failed", str(e))

    def on_rekey(self):
        inpath = self.file_var.get().strip()
        if not inpath or not os.path.isfile(inpath):
            messagebox.showwarning("Missing", "Select the encrypted .db to re-key.")
            return
        old_pp = self._get_passphrase()
        if not old_pp:
            return
        mig_label = self.mig_key_var.get()
        new_pp = MIGRATION_KEYS.get(mig_label)
        if not new_pp:
            messagebox.showerror("Error", f"Unknown key: {mig_label}")
            return
        name, ext = os.path.splitext(os.path.basename(inpath))
        outpath = filedialog.asksaveasfilename(
            title=f"Save re-encrypted ({mig_label})",
            initialfile=f"{name}_{mig_label}{ext or '.db'}",
            initialdir=os.path.dirname(inpath),
            filetypes=[("Database", "*.db"), ("SaveData", "SaveData*"), ("All", "*.*")])
        if not outpath:
            return
        try:
            tables = rekey_db(inpath, outpath, old_pp, new_pp)
            sz = os.path.getsize(outpath)
            self.status_var.set(f"Re-encrypted ({mig_label}): {tables} tables, {sz:,} bytes")
            messagebox.showinfo("Success",
                f"Re-encrypted with {mig_label}!\n\n"
                f"Tables: {tables}\nSize: {sz:,} bytes\n\n"
                f"Game migration will auto-rekey on first load.\n"
                f"⚠ Back up original save before replacing!")
        except Exception as e:
            messagebox.showerror("Re-encrypt failed", str(e))

    def destroy(self):
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
        # Clean up temp files
        if self.working_db and os.path.exists(self.working_db):
            try:
                os.remove(self.working_db)
                tmpdir = os.path.dirname(self.working_db)
                if os.path.isdir(tmpdir) and not os.listdir(tmpdir):
                    os.rmdir(tmpdir)
            except Exception:
                pass
        super().destroy()


if __name__ == "__main__":
    SaveEditorApp().mainloop()
