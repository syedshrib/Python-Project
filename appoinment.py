import tkinter as tk
from tkinter import messagebox
from datetime import datetime

def book_appointment():
    # Get appointment details from the user input
    pet_name = pet_name_entry.get()
    appointment_date = appointment_date_entry.get()
    appointment_time = appointment_time_entry.get()
    appointment_type = appointment_type_var.get()

    # Validate user input
    if not all([pet_name, appointment_date, appointment_time, appointment_type]):
        messagebox.showerror("Error", "Please fill out all fields.")
        return


    # Notify the user of successful appointment booking
    messagebox.showinfo("Success", "Appointment booked successfully!")

# Create the main window
window = tk.Tk()
window.title("Book Appointment")

# Appointment Form
appointment_frame = tk.LabelFrame(window, text="Appointment Details")
appointment_frame.pack(padx=20, pady=10)

pet_name_label = tk.Label(appointment_frame, text="Enter Pet Name:")
pet_name_label.grid(row=0, column=0, padx=5, pady=5)
pet_name_entry = tk.Entry(appointment_frame)
pet_name_entry.grid(row=0, column=1, padx=5, pady=5)

appointment_date_label = tk.Label(appointment_frame, text="Date:")
appointment_date_label.grid(row=1, column=0, padx=5, pady=5)
appointment_date_entry = tk.Entry(appointment_frame)
appointment_date_entry.grid(row=1, column=1, padx=5, pady=5)

appointment_time_label = tk.Label(appointment_frame, text="Time:")
appointment_time_label.grid(row=2, column=0, padx=5, pady=5)
appointment_time_entry = tk.Entry(appointment_frame)
appointment_time_entry.grid(row=2, column=1, padx=5, pady=5)

appointment_type_label = tk.Label(appointment_frame, text="service Type:")
appointment_type_label.grid(row=3, column=0, padx=5, pady=5)
appointment_type_var = tk.StringVar(window)
appointment_type_var.set("Regular Checkup")  # Default value
appointment_type_optionmenu = tk.OptionMenu(appointment_frame, appointment_type_var, "Regular Checkup", "Vaccination", "Grooming")
appointment_type_optionmenu.grid(row=3, column=1, padx=5, pady=5)

# Submit Button
submit_button = tk.Button(window, text="Book Appointment", command=book_appointment)
submit_button.pack(pady=10)

window.mainloop()
