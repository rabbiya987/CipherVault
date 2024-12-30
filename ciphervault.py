import tkinter as tk 
from tkinter import ttk
from PIL import Image, ImageTk 
from crypto import *

class display:
    def __init__(self,root):
        self.root = root
        self.app()


    def app(self):
        #width and height of the application
        app_width, app_height = (635, 430)

        #Getting the screen width and screen height.
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()

        x = (screen_width / 2) - (app_width / 2)
        y = (screen_height / 2) - (app_height / 2)

        # To display the window in center
        root.geometry(f"{app_width}x{app_height}+{int(x)}+{int(y)}")
        root.maxsize(width=app_width, height=app_height)
        self.background()
        self.header()
        self.selection()
        self.Plaintext()
        self.Ciphertext()
        

    def background(self):
        #Adjusting the image
        bg_image = Image.open(r".\Asset\bg(1).jpg")
        bg_image = bg_image.resize((635, 430))
        bg_image_tk = ImageTk.PhotoImage(bg_image)  # Convert image to a Tkinter-compatible format
        
        # Create a Label widget to hold the background image
        background_label = tk.Label(root, image=bg_image_tk)
        background_label.place(x=0, y=0, relwidth=1, relheight=1)
        background_label.image = bg_image_tk

    def header(self):
    # Create a Canvas widget
     header_canvas = tk.Canvas(root, width=635, height=70, bg="#07051a", highlightthickness=0)
     header_canvas.grid(row=0, column=0, columnspan=2, pady=10, padx=10, sticky="ew")

    # Add the main title
     header_canvas.create_text(
        320, 20,  # Coordinates (x, y)
        text="CIPHERVAULT !",
        fill="lightgrey",
        font=("Bahnschrift Condensed", 35, "bold"),
        anchor="center"
     )

    # Add descriptive text
     header_canvas.create_text(
        320, 50,  # Coordinates (x, y)
        text="Secure your data using advanced cryptographic techniques.",
        fill="lightgrey",
        font=("Helvetica", 8),
        anchor="center",
        justify="center"
    )


    def selection(self):
        # Create a mapping of technique names to functions
        self.technique_functions = {
            'XOR Encryption': XOR,
            'Caesar Cipher': CaesarCipher,
            'Base64': Base64Cipher,
            'MD5': MD5,
            'SHA-565': SHA565,
            'AES': AES_Cipher,
            }


        #Creating combobox
        tk.Label(root, text="Select an option:", font=("Helvetica",8,"bold"), bg="#0d092e", fg="white").grid(row=1, column=0, padx=10, pady=5, sticky="w",)
        self.selected_option=tk.StringVar()
        technique_combobox=ttk.Combobox(root,width=15,textvariable=self.selected_option)

        #creating dropdown list by populating it with keys  
        technique_combobox['values']=list(self.technique_functions.keys())

        #Adjusting the combobox
        technique_combobox.grid(column=0, row=1,padx=110, pady=15)
        technique_combobox.current() #Default selection empty

        #button for encrytion
        encrypt_button=tk.Button(root, text="Encrypt", command=self.on_encrypt, font=("Helvetica", 8, "bold"),fg="black",bg="lightgrey",padx=13,relief="raised")
        encrypt_button.grid(row=5, column=0, padx=10, pady=10)

        #Button for decryption
        decrypt_button=tk.Button(root, text="Decrypt", command=self.on_decrypt,font=("Helvetica", 8, "bold"),fg="black",bg="lightgrey",padx=13,relief="raised")
        decrypt_button.grid(row=5, column=1, padx=10, pady=10)
    
    def on_encrypt(self):
        selected=self.selected_option.get()
        encryption=self.technique_functions.get(selected)
        plaintext = self.plaintext_box.get("1.0", tk.END).strip()  # Get plaintext input
        1
        if encryption:
            try:
                encrypted = encryption(plaintext)    #Calling the function of the selected technique
            except Exception as e:
                encrypted = f"Error during encryption: {e}"
        else:
            encrypted = "Invalid technique selected!"

        # Display encrypted text in ciphertext box
        self.cipher_box.delete("1.0", tk.END)  # Clear previous content
        self.cipher_box.insert(tk.END, encrypted) #Display the encrypted text

    def on_decrypt(self):
        selected=self.selected_option.get()
        decryption=self.technique_functions.get(selected)
        Cipher_text = self.cipher_box.get("1.0", tk.END).strip()  # Get Ciphertext input

        if decryption:
            try:
                decrypted = decryption(Cipher_text,decrypt=True) #Calling the function of the selected technique
            except Exception as e:
                decrypted = f"Error during encryption: {e}"
        else:
            decrypted = "Invalid technique selected!"

        # Display decrypted text in ciphertext box
        self.plaintext_box.delete("1.0", tk.END)  # Clear previous content
        self.plaintext_box.insert(tk.END, decrypted) #Display the decrypted text

    def Plaintext(self):
        # Add a label for "Plaintext" and center it horizontally
        plaintext_label = tk.Label(root, text="Plaintext", bg="#07051a", fg="lightgrey", font=("Helvetica", 12, "bold" ),anchor="center")
        plaintext_label.grid(row=2, column=0, padx=10, pady=10, sticky="ew")  # Use "ew" to center horizontally
    
    # Configure the column to stretch so the label centers
        root.grid_columnconfigure(0, weight=1)
    
    # Create a frame for the textbox with styling
        plaintext_frame = tk.Frame(root, bg="white", bd=1, relief="flat")
        plaintext_frame.grid(row=3, column=0, padx=10, pady=5, sticky="nsew")
    
    # Add the text box inside the frame
        self.plaintext_box = tk.Text(plaintext_frame,height=10, width=40, wrap="word", bg="lightgrey", fg="black", font=("Arial", 12, ), bd=3,relief="raised")
        self.plaintext_box.pack(fill="both", expand=True)

        # Add placeholder text
        self.plaintext_box.insert("1.0", "Enter your plaintext here...")



    def Ciphertext(self):
        tk.Label(root, text="Ciphertext",bg="#07051a", fg="lightgrey" ,font=("Helvetica", 12, "bold"),anchor="center").grid(row=2, column=1, padx=10, pady=10, sticky="ew")
        root.grid_columnconfigure(1, weight=1)
         # Frame for text box
        ciphertext_frame = tk.Frame(root,bg="white", bd=1, relief="flat")
        ciphertext_frame.grid(row=3, column=1, padx=10, pady=5, sticky="nsew")
        self.cipher_box = tk.Text(ciphertext_frame, height=10, width=40, wrap="word", bg="lightgrey", fg="black", font=("Arial", 12, ), bd=3,relief="raised")
        self.cipher_box.pack(fill="both", expand=True)
        self.cipher_box.insert("1.0", "Enter your Ciphertext here...")


def main():
    obj=display(root)


if __name__=="__main__":
    root=tk.Tk()
    root.title("CIPHERVAULT BY Rabia Ishtiaq")
    main()
    root.mainloop()
