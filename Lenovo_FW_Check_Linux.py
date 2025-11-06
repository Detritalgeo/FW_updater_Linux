#!/usr/bin/env python3
"""
fwupd-gui.py
Graphical fwupdmgr device + update viewer and updater with Summary Table.

Requirements:
 - Python 3.8+
 - fwupdmgr (from fwupd)
 - Tkinter (usually installed with Python)
"""
import json
import shlex
import shutil
import subprocess
import sys
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, scrolledtext
from typing import Optional, Tuple, List, Dict

# -----------------------
# Utility command helpers
# -----------------------
def run_with_sudo(cmd: str, password: str, timeout: int = 120) -> Tuple[int, str, str]:
    full_cmd = f"sudo -k -S {cmd}"
    proc = subprocess.Popen(shlex.split(full_cmd),
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True)
    try:
        out, err = proc.communicate(password + "\n", timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return 124, out or "", err or ""
    return proc.returncode, out or "", err or ""

def run_no_sudo(cmd: str, timeout: int = 60) -> Tuple[int, str, str]:
    proc = subprocess.run(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    return proc.returncode, proc.stdout or "", proc.stderr or ""

# -----------------------
# UI Helpers
# -----------------------
def ask_password(parent) -> Optional[str]:
    return simpledialog.askstring("Authenticate", "Enter sudo password:", show="*", parent=parent)

# -----------------------
# fwupd JSON helpers
# -----------------------
def fwupd_get_devices_json(password: str) -> Optional[List[Dict]]:
    rc, out, err = run_with_sudo("fwupdmgr get-devices --json", password)
    if rc == 0 and out.strip():
        try:
            data = json.loads(out)
            if isinstance(data, dict) and "Devices" in data:
                return data["Devices"]
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass
    rc2, out2, err2 = run_no_sudo("fwupdmgr get-devices --json")
    if rc2 == 0 and out2.strip():
        try:
            data = json.loads(out2)
            if isinstance(data, dict) and "Devices" in data:
                return data["Devices"]
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass
    rc3, out3, err3 = run_with_sudo("fwupdmgr get-devices", password)
    if rc3 == 0 and out3.strip():
        return parse_fwupd_plain_get_devices(out3)
    return None

def fwupd_get_updates_json(password: str) -> Optional[List[Dict]]:
    rc, out, err = run_with_sudo("fwupdmgr get-updates --json", password)
    if rc == 0 and out.strip():
        try:
            data = json.loads(out)
            if isinstance(data, dict) and "Updates" in data:
                return data["Updates"]
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass
    rc2, out2, err2 = run_no_sudo("fwupdmgr get-updates --json")
    if rc2 == 0 and out2.strip():
        try:
            data = json.loads(out2)
            if isinstance(data, dict) and "Updates" in data:
                return data["Updates"]
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass
    rc3, out3, err3 = run_with_sudo("fwupdmgr get-updates", password)
    if rc3 == 0 and out3.strip():
        return parse_fwupd_plain_get_updates(out3)
    return None

# -----------------------
# Plain-text fallbacks
# -----------------------
def parse_fwupd_plain_get_devices(text: str) -> List[Dict]:
    devices = []
    current = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if "─" in line and line.strip().endswith(":"):
            if current:
                devices.append(current)
            name = line.strip().lstrip("├─").lstrip("└─").rstrip(":").strip()
            current = {"Name": name}
        elif current and ":" in line:
            parts = line.strip().split(":", 1)
            key = parts[0].strip()
            val = parts[1].strip()
            current[key] = val
    if current:
        devices.append(current)
    return devices

def parse_fwupd_plain_get_updates(text: str) -> List[Dict]:
    updates = []
    block = {}
    for line in text.splitlines():
        if not line.strip():
            if block:
                updates.append(block)
                block = {}
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            block[k.strip()] = v.strip()
    if block:
        updates.append(block)
    return updates

# -----------------------
# Mapping functions
# -----------------------
def map_updates_to_devices(devices: List[Dict], updates: List[Dict]) -> Dict[str, List[Dict]]:
    mapping = {}
    dev_by_id = {}
    dev_by_guid = {}
    dev_by_name = {}
    for d in devices:
        did = d.get("DeviceId") or d.get("Device ID") or d.get("DeviceID") or d.get("Id")
        if did:
            dev_by_id[str(did)] = d
        guids = d.get("GUIDs") or d.get("GUID") or d.get("GUIDs")
        if isinstance(guids, list):
            for g in guids:
                dev_by_guid[str(g)] = d
        name = d.get("Name") or d.get("Summary") or d.get("Product")
        if name:
            dev_by_name[str(name)] = d
    for u in updates:
        matched = False
        did = u.get("DeviceId") or u.get("Device ID") or u.get("Device") or u.get("DeviceId")
        if did and str(did) in dev_by_id:
            key = str(did)
            mapping.setdefault(key, []).append(u)
            matched = True
        else:
            gu = u.get("DeviceGUID") or u.get("GUID") or u.get("DeviceGuid")
            if gu and str(gu) in dev_by_guid:
                dev = dev_by_guid[str(gu)]
                did2 = dev.get("DeviceId") or dev.get("Device ID") or dev.get("DeviceID")
                if did2:
                    mapping.setdefault(str(did2), []).append(u)
                    matched = True
            else:
                name = u.get("Device") or u.get("Product")
                if name and str(name) in dev_by_name:
                    dev = dev_by_name[str(name)]
                    did2 = dev.get("DeviceId") or dev.get("Device ID") or dev.get("DeviceID")
                    if did2:
                        mapping.setdefault(str(did2), []).append(u)
                        matched = True
        if not matched:
            mapping.setdefault("unknown", []).append(u)
    return mapping

# -----------------------
# GUI implementation
# -----------------------
class FWUpdateGUI(tk.Tk):
    def __init__(self, password: str):
        super().__init__()
        self.title("fwupd device viewer")
        self.geometry("1000x650")
        self.password = password
        self.devices = []
        self.updates = []
        self.mapping = {}
        self.create_widgets()
        self.refresh_data()

    def create_widgets(self):
        frm = ttk.Frame(self)
        frm.pack(fill="x", padx=6, pady=6)

        self.refresh_btn = ttk.Button(frm, text="Refresh", command=self.refresh_data)
        self.refresh_btn.pack(side="left")

        self.summary_btn = ttk.Button(frm, text="Summary Table", command=self.show_summary_table)
        self.summary_btn.pack(side="left", padx=(6,0))

        self.update_all_btn = ttk.Button(frm, text="Update All (sudo)", command=self.update_all)
        self.update_all_btn.pack(side="left", padx=(6,0))

        self.status_lbl = ttk.Label(frm, text="Status: ready")
        self.status_lbl.pack(side="right")

        pan = ttk.PanedWindow(self, orient="horizontal")
        pan.pack(fill="both", expand=True, padx=6, pady=6)

        left = ttk.Frame(pan)
        right = ttk.Frame(pan)
        pan.add(left, weight=1)
        pan.add(right, weight=2)

        self.tree = ttk.Treeview(left, columns=("vendor","version","updatable"), show="headings")
        self.tree.heading("vendor", text="Vendor")
        self.tree.heading("version", text="Version")
        self.tree.heading("updatable", text="Updates")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        self.details = scrolledtext.ScrolledText(right, wrap="word")
        self.details.pack(fill="both", expand=True)

        btn_fr = ttk.Frame(right)
        btn_fr.pack(fill="x")
        self.run_update_btn = ttk.Button(btn_fr, text="Run Update for Selected", command=self.update_selected)
        self.run_update_btn.pack(side="left", padx=4, pady=4)
        self.open_log_btn = ttk.Button(btn_fr, text="Show fwupdmgr logs (journalctl)", command=self.show_logs)
        self.open_log_btn.pack(side="left", padx=4)

    def set_status(self, text: str):
        self.status_lbl.config(text=f"Status: {text}")
        self.update_idletasks()

    def refresh_data(self):
        self.set_status("refreshing (fwupdmgr)...")
        self.devices = fwupd_get_devices_json(self.password) or []
        self.updates = fwupd_get_updates_json(self.password) or []
        self.mapping = map_updates_to_devices(self.devices, self.updates)
        for i in self.tree.get_children():
            self.tree.delete(i)
        for d in self.devices:
            name = d.get("Name") or d.get("Summary") or d.get("Id") or d.get("Product") or "Unknown device"
            vendor = d.get("Vendor") or d.get("VendorName") or ""
            version = d.get("CurrentVersion") or d.get("Current version") or d.get("Current version") or ""
            did = d.get("DeviceId") or d.get("Device ID") or d.get("DeviceID") or d.get("Id") or name
            updates_for = self.mapping.get(str(did)) or []
            up_text = str(len(updates_for))
            iid = str(did) if did else name
            self.tree.insert("", "end", iid=iid, values=(vendor, version, up_text), text=name)
        total_updates = sum(len(v) for v in self.mapping.values())
        self.set_status(f"found {len(self.devices)} devices, {total_updates} updates")

    def on_select(self, _evt=None):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        d = None
        for dev in self.devices:
            did = dev.get("DeviceId") or dev.get("Device ID") or dev.get("DeviceID") or dev.get("Id") or dev.get("Name") or dev.get("Summary")
            if str(did) == iid or (not did and (dev.get("Name") == iid or dev.get("Summary") == iid)):
                d = dev
                break
        if not d and self.devices:
            d = self.devices[0]
        parts = []
        parts.append(f"Name: {d.get('Name') or d.get('Summary') or 'Unknown'}")
        for k in sorted(d.keys()):
            parts.append(f"{k}: {d[k]}")
        updates = self.mapping.get(str(d.get("DeviceId") or d.get("Device ID") or d.get("DeviceID") or d.get("Id") or ""), [])
        parts.append("\nUpdates:")
        if updates:
            for u in updates:
                parts.append(json.dumps(u, indent=2))
        else:
            parts.append("  None")
        self.details.delete("1.0", tk.END)
        self.details.insert(tk.END, "\n".join(parts))

    def update_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("fwupd", "No device selected")
            return
        if not messagebox.askyesno("Confirm", "Run fwupdmgr update now? This will run fwupdmgr update for the system."):
            return
        self.set_status("running fwupdmgr update...")
        rc, out, err = run_with_sudo("fwupdmgr update", self.password, timeout=900)
        if rc == 0:
            messagebox.showinfo("fwupd", "fwupdmgr update completed successfully. Reboot may be required.")
            self.refresh_data()
        else:
            messagebox.showerror("fwupd", f"fwupdmgr update failed (rc={rc}). See output window.")
            self.details.delete("1.0", tk.END)
            self.details.insert(tk.END, f"STDOUT:\n{out}\n\nSTDERR:\n{err}")

    def update_all(self):
        if not messagebox.askyesno("Confirm", "Run fwupdmgr update for all updates now? This requires sudo and may reboot device for some updates."):
            return
        self.set_status("running fwupdmgr update (all)...")
        rc, out, err = run_with_sudo("fwupdmgr update", self.password, timeout=900)
        if rc == 0:
            messagebox.showinfo("fwupd", "fwupdmgr update completed successfully.")
            self.refresh_data()
        else:
            messagebox.showerror("fwupd", f"fwupdmgr update failed (rc={rc}). See output in details.")
            self.details.delete("1.0", tk.END)
            self.details.insert(tk.END, f"STDOUT:\n{out}\n\nSTDERR:\n{err}")

    def show_logs(self):
        rc, out, err = run_no_sudo("journalctl -u fwupd -n 200 --no-pager")
        if rc != 0:
            out = err or "Could not fetch journal (try running as root)"
        win = tk.Toplevel(self)
        win.title("fwupd logs (journalctl)")
        txt = scrolledtext.ScrolledText(win, wrap="none", width=120, height=40)
        txt.pack(fill="both", expand=True)
        txt.insert("1.0", out)

    # -----------------------
    # Summary Table popup
    # -----------------------
    def show_summary_table(self):
        """Open a popup with a concise summary table of devices and update counts."""
        win = tk.Toplevel(self)
        win.title("fwupd Summary Table")
        win.geometry("800x400")

        cols = ("name", "vendor", "version", "updates")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        tree.heading("name", text="Name")
        tree.heading("vendor", text="Vendor")
        tree.heading("version", text="Current Version")
        tree.heading("updates", text="Updates")

        tree.column("name", width=360, anchor="w")
        tree.column("vendor", width=150, anchor="w")
        tree.column("version", width=130, anchor="center")
        tree.column("updates", width=70, anchor="center")

        vsb = ttk.Scrollbar(win, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(win, orient="horizontal", command=tree.xview)
        tree.configure(yscroll=vsb.set, xscroll=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        win.grid_rowconfigure(0, weight=1)
        win.grid_columnconfigure(0, weight=1)

        for d in self.devices:
            name = d.get("Name") or d.get("Summary") or d.get("Product") or "Unknown"
            vendor = d.get("Vendor") or d.get("VendorName") or ""
            version = (d.get("CurrentVersion") or d.get("Current version") or "").strip()
            did = d.get("DeviceId") or d.get("Device ID") or d.get("DeviceID") or d.get("Id") or name
            updates_for = self.mapping.get(str(did)) or []
            up_text = str(len(updates_for))
            tree.insert("", "end", values=(name, vendor, version, up_text))

        def copy_to_clipboard():
            lines = ["Name\tVendor\tVersion\tUpdates"]
            for row in tree.get_children():
                vals = tree.item(row, "values")
                lines.append("\t".join(str(v) for v in vals))
            self.clipboard_clear()
            self.clipboard_append("\n".join(lines))
            messagebox.showinfo("Copied", "Summary copied to clipboard (TSV).")

        btn_fr = ttk.Frame(win)
        btn_fr.grid(row=2, column=0, columnspan=2, pady=6, sticky="ew")
        ttk.Button(btn_fr, text="Copy as TSV", command=copy_to_clipboard).pack(side="left", padx=6)
        ttk.Button(btn_fr, text="Close", command=win.destroy).pack(side="right", padx=6)

# -----------------------
# Main
# -----------------------
def main():
    if shutil.which("fwupdmgr") is None:
        tk.messagebox.showerror("Missing dependency", "fwupdmgr is not installed or not in PATH.")
        sys.exit(1)

    root = tk.Tk()
    root.withdraw()
    pwd = ask_password(root)
    if pwd is None:
        messagebox.showinfo("Cancelled", "No password entered; exiting.")
        sys.exit(2)
    root.destroy()

    app = FWUpdateGUI(pwd)
    app.mainloop()

if __name__ == "__main__":
    main()
