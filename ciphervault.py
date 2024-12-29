import tkinter as tk 
from tkinter import ttk
from Theme import *
from PIL import Image, ImageTk 
from crypto import *

def main():
    obj=display()
    obj.app()
    obj.Plaintext()
    obj.Ciphertext()
    obj.selection()

class display:
    def app(self):
        #width and height of the application
        app_width, app_height = (850, 450)

        #Getting the screen width and screen height.
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()

        x = (screen_width / 2) - (app_width / 2)
        y = (screen_height / 2) - (app_height / 2)

        # To display the window in center
        root.geometry(f"{app_width}x{app_height}+{int(x)}+{int(y)}")
        root.maxsize(width=app_width, height=app_height)
        #Background Colour
        root.config(bg=BODY_COLOR)
        self.background()
        self.header()
        

    def background(self):
        bg_image = Image.open(r".\Asset\bg.jpeg")  # Replace with the path to your image
        bg_image = bg_image.resize((850, 450))  # Resize the image to fit the window size
        bg_image_tk = ImageTk.PhotoImage(bg_image)  # Convert image to a Tkinter-compatible format
        
        # Create a Label widget to hold the background image
        background_label = tk.Label(root, image=bg_image_tk)
        background_label.place(x=0, y=0, relwidth=1, relheight=1)  # Place the background label at the bottom of the window

        # Keep a reference to the image to prevent it from being garbage collected
        background_label.image = bg_image_tk

    def header(self):
        header_label=tk.Label(root, text="CIPHERVAULT", font=("Arial", 24, "bold"))
        header_label.grid(row=0, column=0, columnspan=2, pady=10, padx=10, sticky="nsew")
        

    def selection(self):
        # Create a mapping of technique names to functions
        self.technique_functions = {
            'AES (Advanced Encryption Standard)':AES,
            'RSA (Rivest–Shamir–Adleman)':XOR,
            'Caesar Cipher':Base64,
        }

        #Creating combobox
        tk.Label(root, text="Select an option:").grid(row=1, column=0, padx=10, pady=5, sticky="w",)
        selected_option=tk.StringVar()
        technique_combobox=ttk.Combobox(root,width=20,textvariable=selected_option)

        #creating dropdown list by populating it with keys  
        technique_combobox['values']=(self.technique_functions.keys())

        #Adjusting the combobox
        technique_combobox.grid(column=1, row=1,padx=10, pady=15)
        technique_combobox.current() #Default selection empty

        technique_combobox.bind("<<ComboboxSelected>>", self.on_select)
    
    def on_select(self,event):
        selected=self.selected_option.get()
        encryption=self.technique_functions.get(selected)
        plaintext=self.plaintext_box.get("1.0".tk.END).strip() # Get plaintext input

        if encryption:
            try:
                encrypted = encryption(plaintext)  # Call the selected function
            except Exception as e:
                encrypted = f"Error during encryption: {e}"
        else:
            encrypted = "Invalid technique selected!"

        # Display encrypted text in ciphertext box
        self.cipher_box.delete("1.0", tk.END)  # Clear previous content
        self.cipher_box.insert(tk.END, encrypted)


    def Plaintext(self):
        tk.Label(root, text="Plaintext").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        plaintext_box=tk.Text(root, height=10, width=40, wrap="word")
        plaintext_box.grid(row=3, column=0, padx=10, pady=5, sticky="nsew")

    def Ciphertext(self):
        tk.Label(root, text="Ciphertext").grid(row=2, column=1, padx=10, pady=5, sticky="w")
        cipher_box=tk.Text(root, height=10, width=40, wrap="word")
        cipher_box.grid(row=3, column=1, padx=10, pady=5, sticky="nsew")


if __name__=="__main__":
    root=tk.Tk()
    root.title("CIPHERVAULT")
    main()
    root.mainloop()
