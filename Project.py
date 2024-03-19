import tkinter as tk
import mysql.connector
import re
from tkinter import messagebox


class PetCareApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Pet Care Management System")
        self.root.geometry("350x250")

        self.setup_ui()

    def setup_ui(self):
        self.home_frame = tk.Frame(self.root)
        self.home_frame.place(relx=0.5, rely=0.25, anchor=tk.CENTER)

        tk.Label(self.home_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.home_username_entry = tk.Entry(self.home_frame)
        self.home_username_entry.grid(row=0, column=1, pady=2, padx=5)

        tk.Label(self.home_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.home_password_entry = tk.Entry(self.home_frame, show="*")
        self.home_password_entry.grid(row=1, column=1, pady=2, padx=5)

        self.login_role_var = tk.StringVar(value="user")
        self.login_role_frame = tk.Frame(self.home_frame)
        self.login_role_frame.grid(row=2, column=1, sticky=tk.W, pady=2)
        tk.Radiobutton(self.login_role_frame, text="User", variable=self.login_role_var, value="user").pack(
            side=tk.LEFT)
        tk.Radiobutton(self.login_role_frame, text="Admin", variable=self.login_role_var, value="admin").pack(
            side=tk.LEFT)

        button_frame = tk.Frame(self.home_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        tk.Button(button_frame, text="Register", command=self.show_register_form).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Login", command=self.login_user_from_home).pack(side=tk.LEFT, padx=5)

    def connect_db(self):
        try:
            return mysql.connector.connect(
                host='LAPTOP-I8MG72D',
                user='root',
                passwd='Fallfall@2022',
                database='petcare_management_system'
            )
        except mysql.connector.Error as e:
            messagebox.showerror("Database Connection Error", str(e))
            return None

    def show_register_form(self):
        self.clear_ui()

        self.register_frame = tk.Frame(self.root)
        self.register_frame.pack(fill=tk.BOTH, expand=True)

        self.role_var = tk.StringVar(value="user")
        role_frame = tk.Frame(self.register_frame)
        role_frame.pack(pady=5)
        tk.Radiobutton(role_frame, text="User", variable=self.role_var, value="user").pack(side=tk.LEFT)
        tk.Radiobutton(role_frame, text="Admin", variable=self.role_var, value="admin").pack(side=tk.LEFT)

        tk.Label(self.register_frame, text="Username:").pack()
        self.reg_username_entry = tk.Entry(self.register_frame)
        self.reg_username_entry.pack()

        tk.Label(self.register_frame, text="Email Address:").pack()
        self.reg_email_entry = tk.Entry(self.register_frame)
        self.reg_email_entry.pack()

        tk.Label(self.register_frame, text="Password:").pack()
        self.reg_password_entry = tk.Entry(self.register_frame, show="*")
        self.reg_password_entry.pack()

        tk.Label(self.register_frame, text="First Name:").pack()
        self.reg_firstname_entry = tk.Entry(self.register_frame)
        self.reg_firstname_entry.pack()

        tk.Label(self.register_frame, text="Last Name:").pack()
        self.reg_lastname_entry = tk.Entry(self.register_frame)
        self.reg_lastname_entry.pack()

        # Frame for action buttons
        action_frame = tk.Frame(self.register_frame)
        action_frame.pack(pady=10)
        tk.Button(action_frame, text="Register", command=self.register_user).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="Back", command=self.back_to_home).pack(side=tk.LEFT, padx=5)

    def login_user_from_home(self):
        username = self.home_username_entry.get()
        password = self.home_password_entry.get()
        role = self.login_role_var.get()
        self.login_user(username, password, role)

    def clear_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def register_user(self):
        username = self.reg_username_entry.get()
        email = self.reg_email_entry.get()
        password = self.reg_password_entry.get()
        firstname = self.reg_firstname_entry.get()
        lastname = self.reg_lastname_entry.get()
        role = self.role_var.get()

        email_regex = r'^.+@.+\..+$'
        if not re.match(email_regex, email):
            messagebox.showerror("Error", "Invalid email format.")
            return

        # Password strength validation
        password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$'  # Modify as needed
        if not re.fullmatch(password_regex, password):
            messagebox.showerror("Error",
                                 "Password must be at least 8 characters long and include one lowercase letter, one uppercase letter, and one digit.")
            return

        conn = self.connect_db()
        if conn is not None:
            cursor = conn.cursor()
            try:
                # Check if the username already exists
                cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                if cursor.fetchone():
                    messagebox.showerror("Error", "Username already exists.")
                    return

                # Insert new user into the database
                insert_query = ("INSERT INTO users (username, email, password, firstname, lastname, role) "
                                "VALUES (%s, %s, %s, %s, %s, %s)")
                cursor.execute(insert_query, (username, email, password, firstname, lastname, role))
                conn.commit()
                messagebox.showinfo("Success", "Registered successfully as {}.".format(role))
            except mysql.connector.Error as e:
                messagebox.showerror("Database Error", str(e))
            finally:
                cursor.close()
                conn.close()

        self.clear_ui()
        self.setup_ui()

    def login_user(self, username, password, role):
        conn = self.connect_db()
        if conn is not None:
            cursor = conn.cursor()
            try:
                # Select user from the database with the provided credentials
                query = "SELECT * FROM users WHERE username = %s AND password = %s AND role = %s"
                cursor.execute(query, (username, password, role))
                account = cursor.fetchone()
                if account:
                    messagebox.showinfo("Login Successful", "Logged in as {}.".format(role))
                else:
                    messagebox.showerror("Login Failed", "Invalid login details.")
            except mysql.connector.Error as e:
                messagebox.showerror("Database Error", str(e))
            finally:
                cursor.close()
                conn.close()

    def back_to_home(self):
        self.clear_ui()
        self.setup_ui()


def run_app():
    root = tk.Tk()
    app = PetCareApp(root)
    root.mainloop()


run_app()