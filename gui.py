import tkinter as tk
from tkinter import messagebox, scrolledtext
import subprocess
import os

APP_TITLE = "OTP-Based Secure Login System"

class App:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("420x320")
        self.root.resizable(False, False)
        self.role = None
        self.proc = None
        
        # Handle Window Close (X button)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.show_main_menu()

    def on_close(self):
        """
        Deterministcally cleans up the subprocess.
        1. Checks if process exists and is running.
        2. Sends SIGTERM.
        3. Waits for OS to release the handle (prevents zombies).
        4. Force kills if SIGTERM is ignored.
        """
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                # Wait up to 1 second for graceful exit
                self.proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                # If it's stuck, force kill it
                self.proc.kill()
        self.root.destroy()

    def clean_input(self, text):
        return text.strip().replace("\n", "").replace(" ", "")

    def clear(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_main_menu(self):
        self.clear()
        tk.Label(self.root, text=APP_TITLE, font=("Arial", 14, "bold")).pack(pady=20)
        tk.Button(self.root, text="Login", width=25, command=self.show_login).pack(pady=5)
        tk.Button(self.root, text="Register", width=25, command=self.show_register).pack(pady=5)
        tk.Button(self.root, text="Exit", width=25, command=self.on_close).pack(pady=20)

    def show_register(self):
        self.clear()
        tk.Label(self.root, text="Create New Account", font=("Arial", 14, "bold")).pack(pady=10)

        tk.Label(self.root, text="Username").pack()
        self.reg_user = tk.Entry(self.root)
        self.reg_user.pack()

        tk.Label(self.root, text="Password").pack()
        self.reg_pass = tk.Entry(self.root, show="*")
        self.reg_pass.pack()

        tk.Button(self.root, text="Register", command=self.handle_register).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.show_main_menu).pack()

    def handle_register(self):
        username = self.clean_input(self.reg_user.get())
        password = self.clean_input(self.reg_pass.get())

        if not username or not password:
            messagebox.showerror("Error", "Invalid or empty input")
            return

        try:
            # We use 'with' or manual wait here, but manual gives us more control over streams
            proc = subprocess.Popen(
                ["auth.exe"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True
            )

            proc.stdin.write(f"REGISTER\n{username}\n{password}\n")
            proc.stdin.flush()

            output = proc.stdout.read()
            proc.wait() # Ensure we reap the process

            if "STATUS:SUCCESS" in output:
                messagebox.showinfo("Success", "Account created successfully")
                self.show_main_menu()
            else:
                if "USER_EXISTS" in output:
                    err = "User already exists"
                else:
                    err = "Registration failed"
                messagebox.showerror("Error", err)
        except FileNotFoundError:
             messagebox.showerror("Error", "auth.exe not found! Compile the C code first.")

    def show_login(self):
        self.clear()
        tk.Label(self.root, text="Login", font=("Arial", 14, "bold")).pack(pady=10)

        tk.Label(self.root, text="Username").pack()
        self.login_user = tk.Entry(self.root)
        self.login_user.pack()

        tk.Label(self.root, text="Password").pack()
        self.login_pass = tk.Entry(self.root, show="*")
        self.login_pass.pack()

        tk.Button(self.root, text="Login", command=self.handle_login).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.show_main_menu).pack()

    def handle_login(self):
        username = self.clean_input(self.login_user.get())
        password = self.clean_input(self.login_pass.get())

        if not username or not password:
            messagebox.showerror("Error", "Invalid or empty input")
            return

        try:
            self.proc = subprocess.Popen(
                ["auth.exe"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True
            )

            self.proc.stdin.write(f"LOGIN\n{username}\n{password}\n")
            self.proc.stdin.flush()

            line = self.proc.stdout.readline()
            if "STATUS:OTP_REQUIRED" not in line:
                messagebox.showerror("Login Failed", "Invalid credentials")
                self.proc.kill()
                self.proc = None
                return

            role_line = self.proc.stdout.readline()
            self.role = role_line.split(":")[1].strip()

            messagebox.showinfo(
                "OTP Sent",
                "OTP has been sent to your registered email.\n(Open simulated_email.txt)"
            )

            self.show_otp_screen()
        except FileNotFoundError:
            messagebox.showerror("Error", "auth.exe not found! Compile the C code first.")

    def show_otp_screen(self):
        self.clear()
        tk.Label(self.root, text="OTP Verification", font=("Arial", 14, "bold")).pack(pady=10)
        tk.Label(self.root, text="Enter OTP").pack()
        self.otp_entry = tk.Entry(self.root)
        self.otp_entry.pack()
        tk.Button(self.root, text="Verify OTP", command=self.verify_otp).pack(pady=10)

    def verify_otp(self):
        otp = self.clean_input(self.otp_entry.get())
        
        if not otp: 
             messagebox.showwarning("Input Error", "Please enter the OTP")
             return

        try:
            self.proc.stdin.write(f"{otp}\n")
            self.proc.stdin.flush()

            response = self.proc.stdout.readline()

            if "STATUS:SUCCESS" in response:
                messagebox.showinfo("Success", f"Login successful ({self.role})")
                self.proc.kill()
                self.proc = None
                self.show_dashboard()
            elif "STATUS:RETRY" in response:
                messagebox.showwarning("Retry", "Incorrect OTP")
                # Clear entry to prevent accidental double-submit
                self.otp_entry.delete(0, tk.END)
            else:
                messagebox.showerror("Failed", "Authentication failed or Timed Out")
                self.proc.kill()
                self.proc = None
                self.show_main_menu()
        except (BrokenPipeError, OSError):
            messagebox.showerror("Error", "Connection to backend lost (Process died)")
            self.show_main_menu()

    def show_dashboard(self):
        self.clear()
        tk.Label(self.root, text="Dashboard", font=("Arial", 14, "bold")).pack(pady=10)
        tk.Label(self.root, text=f"Role: {self.role}").pack(pady=5)

        if self.role == "admin":
            tk.Button(self.root, text="View Logs", width=25, command=self.show_logs).pack(pady=5)

        tk.Button(self.root, text="Logout", width=25, command=self.show_main_menu).pack(pady=20)

    def show_logs(self):
        if not os.path.exists("logs.txt"):
            messagebox.showerror("Error", "logs.txt not found")
            return

        log_window = tk.Toplevel(self.root)
        log_window.title("Audit Logs")
        log_window.geometry("600x400")

        txt = scrolledtext.ScrolledText(log_window, wrap=tk.WORD)
        txt.pack(expand=True, fill="both")

        with open("logs.txt", "r") as f:
            txt.insert(tk.END, f.read())

        txt.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()