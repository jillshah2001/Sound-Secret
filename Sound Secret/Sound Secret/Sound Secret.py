import subprocess
import threading
from turtle import onclick
import customtkinter
import os
from tkinter import filedialog
from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import b64decode, b64encode
import wave, random, sys, quantumrandom
import secrets
import shutil
from crypto.Cipher import ChaCha20 , PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import rsa
from crypto.PublicKey import RSA


class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("Sound Secret - Audio Crypt")
        self.geometry("700x700")


        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)


        image_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "images")
        self.logo_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "CustomTkinter_logo_single.png")), size=(26, 26))
        self.large_test_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "large_test_image.png")), size=(500, 150))
        self.image_icon_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "image_icon_light.png")), size=(20, 20))
        self.key_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "key.png")), size=(50, 50))
        self.audio_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "audio.png")), size=(50, 50))
        self.select_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "select.png")), size=(50, 50))
        self.image_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "image.png")), size=(50, 50))
        self.embed_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "embed.png")), size=(50, 50))
        self.upload_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "upload.png")), size=(50, 50))
        self.decrypt_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "decrypt.png")), size=(50, 50))
        self.home_image = customtkinter.CTkImage(light_image=Image.open(os.path.join(image_path, "home_dark.png")),
                                                 dark_image=Image.open(os.path.join(image_path, "home_light.png")), size=(20, 20))
        self.chat_image = customtkinter.CTkImage(light_image=Image.open(os.path.join(image_path, "chat_dark.png")),
                                                 dark_image=Image.open(os.path.join(image_path, "chat_light.png")), size=(20, 20))
        self.add_user_image = customtkinter.CTkImage(light_image=Image.open(os.path.join(image_path, "add_user_dark.png")),
                                                     dark_image=Image.open(os.path.join(image_path, "add_user_light.png")), size=(20, 20))

        # Navigation frame
        self.navigation_frame = customtkinter.CTkFrame(self, corner_radius=0)
        self.navigation_frame.grid(row=0, column=0, sticky="nsew")
        self.navigation_frame.grid_rowconfigure(4, weight=1)

        self.navigation_frame_label = customtkinter.CTkLabel(self.navigation_frame, text="  Menu", image=self.logo_image,
                                                             compound="left", font=customtkinter.CTkFont(size=15, weight="bold"))
        self.navigation_frame_label.grid(row=0, column=0, padx=20, pady=20)

        self.home_button = customtkinter.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Home",
                                                   fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                   image=self.home_image, anchor="w", command=self.home_button_event)
        self.home_button.grid(row=1, column=0, sticky="ew")

        self.sender_button = customtkinter.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Sender",
                                                      fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                      image=self.chat_image, anchor="w", command=self.sender_button_event)
        self.sender_button.grid(row=2, column=0, sticky="ew")

        self.reciever_button = customtkinter.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Reciever",
                                                      fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                      image=self.add_user_image, anchor="w", command=self.reciever_button_event)
        self.reciever_button.grid(row=3, column=0, sticky="ew")

        self.appearance_mode_menu = customtkinter.CTkOptionMenu(self.navigation_frame, values=["Light", "Dark", "System"],
                                                                command=self.change_appearance_mode_event)
        self.appearance_mode_menu.grid(row=6, column=0, padx=20, pady=20, sticky="s")

        # Home frame
        self.home_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.home_frame.grid_columnconfigure(0, weight=1)

        self.home_frame_large_image_label = customtkinter.CTkLabel(self.home_frame, text="", image=self.large_test_image)
        self.home_frame_large_image_label.grid(row=0, column=0, padx=20, pady=10)

        self.home_frame_button_1 = customtkinter.CTkButton(self.home_frame, text="RSA Key Generation", image=self.key_image, compound="top", corner_radius=32, command=newkeys)
        self.home_frame_button_1.grid(row=1, column=0, padx=20, pady=10)
        self.home_frame_button_2 = customtkinter.CTkButton(self.home_frame, text="Analyze Audio", image=self.audio_image, compound="top", corner_radius=32,command=analyseAudio)
        self.home_frame_button_2.grid(row=2, column=0, padx=20, pady=10)


        # Sender frame

        self.sender_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.sender_frame.grid_columnconfigure(0, weight=1)

        self.sender_frame_large_image_label = customtkinter.CTkLabel(self.sender_frame, text="", image=self.large_test_image)
        self.sender_frame_large_image_label.grid(row=0, column=0, padx=20, pady=10)

        self.sender_frame_button_3 = customtkinter.CTkButton(self.sender_frame, text="Select Audio File", image=self.select_image, compound="top", corner_radius=32 , command=select_audio_file)
        self.sender_frame_button_3.grid(row=1, column=0, padx=20, pady=10)
        self.sender_frame_button_4 = customtkinter.CTkButton(self.sender_frame, text="Select Image File", image=self.image_image, compound="top", corner_radius=32 , command=select_image_file)
        self.sender_frame_button_4.grid(row=2, column=0, padx=20, pady=10)
        self.sender_frame_button_5 = customtkinter.CTkButton(self.sender_frame, text="Select Public Key", image=self.key_image, compound="top", corner_radius=32 ,command=select_key_file )
        self.sender_frame_button_5.grid(row=3, column=0, padx=20, pady=10)
        self.sender_frame_button_6 = customtkinter.CTkButton(self.sender_frame, text="Embed Audio", image=self.embed_image, compound="top", corner_radius=32, command=embed_audio)
        self.sender_frame_button_6.grid(row=4, column=0, padx=20, pady=10)
        
        


        # Reciever frame
        self.reciever_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.reciever_frame.grid_columnconfigure(0, weight=1)

        self.reciever_frame_large_image_label = customtkinter.CTkLabel(self.reciever_frame, text="", image=self.large_test_image)
        self.reciever_frame_large_image_label.grid(row=0, column=0, padx=20, pady=10)

        self.reciever_frame_button_7 = customtkinter.CTkButton(self.reciever_frame, text="Upload Audio File", image=self.upload_image, compound="top", corner_radius=32,command=save_audio_file)
        self.reciever_frame_button_7.grid(row=2, column=0, padx=20, pady=10)
        self.reciever_frame_button_8 = customtkinter.CTkButton(self.reciever_frame, text="Select Private Key", image=self.key_image, compound="top", corner_radius=32,command=save_private_key)
        self.reciever_frame_button_8.grid(row=3, column=0, padx=20, pady=10)
        self.reciever_frame_button_9 = customtkinter.CTkButton(self.reciever_frame, text="Decrypt", image=self.decrypt_image, compound="top", corner_radius=32,command=lambda:decode_audio(private_key))
        self.reciever_frame_button_9.grid(row=4, column=0, padx=20, pady=10)

        # Default frame
        self.select_frame_by_name("home")

    def select_frame_by_name(self, name):
        self.home_button.configure(fg_color=("gray75", "gray25") if name == "home" else "transparent")
        self.sender_button.configure(fg_color=("gray75", "gray25") if name == "sender" else "transparent")
        self.reciever_button.configure(fg_color=("gray75", "gray25") if name == "reciever" else "transparent")

        if name == "home":
            self.home_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.home_frame.grid_forget()
        if name == "sender":
            self.sender_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.sender_frame.grid_forget()
        if name == "reciever":
            self.reciever_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.reciever_frame.grid_forget()

    def home_button_event(self):
        self.select_frame_by_name("home")

    def sender_button_event(self):
        self.select_frame_by_name("sender")

    def reciever_button_event(self):
        self.select_frame_by_name("reciever")

    def change_appearance_mode_event(self, new_appearance_mode):
        customtkinter.set_appearance_mode(new_appearance_mode)
        
#Sender Page  
     
input_img = ''
audio = ''
public_key = ''

def encrypt(message, pub_key):
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(message)

def import_key(extern_key):
    return RSA.importKey(extern_key)

def select_audio_file():
    global audio
    audio = filedialog.askopenfilename(filetypes=[("Audio files", "*.wav *.mp3")])

def select_image_file():
    global input_img
    input_img = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg *.png")])

def select_key_file():
    global public_key
    public_key = filedialog.askopenfilename(filetypes=[("Key files", "*.pem")])
    os.mkdir("temp")
    shutil.copy(input_img, os.path.join("temp"))

def embed_audio():
    if not (input_img and audio and public_key):
        print("Please select audio file, image file, and public key.")
        return

    song = wave.open(audio, mode='rb')
    frame_bytes = bytearray(list(song.readframes(song.getnframes())))

    with open(input_img, "rb") as image:
        string = b64encode(image.read()).decode('utf-8')     
        
    ################ LOCAL ################
    key = secrets.token_bytes(32)
    ######################################
    cipher = ChaCha20.new(key=key)
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ciphertext = cipher.encrypt(string.encode())
    ct = b64encode(ciphertext).decode('utf-8')
    bits = list(map(int, ''.join([bin(ord(i)).lstrip('0b').rjust(8, '0') for i in ct])))

    indices = [i for i in range(0, len(frame_bytes))]
    seed = quantumrandom.get_data()[0]
    random.Random(seed).shuffle(indices)

    for i, bit in enumerate(bits):
        loc = indices[i]
        frame_bytes[loc] = (frame_bytes[loc] & 254) | bit

    frame_modified = bytes(frame_bytes)

    with wave.open('sample_embedded_img3.wav', 'wb') as fd:
        fd.setparams(song.getparams())
        fd.writeframes(frame_modified)

    song.close()

    final_key = str(int.from_bytes(key, byteorder=sys.byteorder)) + "." + str(nonce) + "." + str(len(bits)) + "." + str(seed)
    public_key_obj = import_key(open(public_key).read())
    c = encrypt(final_key.encode(), public_key_obj)
    c = str(b64encode(c)).lstrip("b'").rstrip("'")

    with open('encryption.txt', 'w') as f:
        f.write(str(c))

    print("Encrypted Message Saved..")    

#Receiver Page
audio_loc = ""
private_key = ""

def save_audio_file():
    global audio_loc
    audio_loc = filedialog.askopenfilename(filetypes=[("Audio files", "*.wav *.mp3")])

def save_private_key():
    global private_key
    private_key = filedialog.askopenfilename(filetypes=[("Key files", "*.pem")])

def Back_thread():
    subprocess.call(["python", "Home.py"])

def open_Back_script():
    thread = threading.Thread(target=Back_thread)
    thread.start()

def decrypt(ciphertext, priv_key):
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(ciphertext)

def importKey(externKey):
    return RSA.importKey(externKey)

def get_keys():
    key_path = open(private_key).read()
    private_key_obj = importKey(key_path)
    ciphertext = open('encryption.txt').read()
    
    # Ensure proper base64 padding by adding '=' characters
    while len(ciphertext) % 4 != 0:
        ciphertext += '='

    d = decrypt(b64decode(ciphertext), private_key_obj)
    return str(d.decode()), private_key_obj

def decode_audio(private_key_path):
    global audio_loc
    ext = '.jpg'
    song = wave.open(audio_loc, mode='rb')
    frame_bytes = bytearray(list(song.readframes(song.getnframes())))

    keys, private_key_obj = get_keys()
    chacha20_key = int(keys[0]).to_bytes(32, byteorder=sys.byteorder)
    nonce = keys[1]
    l1 = int(keys[2])

    indices = [i for i in range(0, len(frame_bytes))]
    random.Random().shuffle(indices)

    extracted = []
    for i in range(0, l1):
        loc = indices[i]
        extracted.append(frame_bytes[loc] & 1)

    string = "".join(chr(int("".join(map(str, extracted[i:i+8])), 2)) for i in range(0, len(extracted), 8))

    try:
        print("Ciphertext Length:", len(string))
        nonce = b64decode(nonce)
        ciphertext = b64decode(string.encode('utf-8'))
        print("RSA Private Key Size:", private_key_obj.size_in_bits())
        cipher_rsa = PKCS1_OAEP.new(private_key_obj)
        symmetric_key = cipher_rsa.decrypt(chacha20_key)

        cipher = ChaCha20.new(key=symmetric_key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)

        decoded_image_data = b64decode(plaintext)

        with open('decoded_image' + ext, 'wb') as decodeit:
            decodeit.write(decoded_image_data)

    except Exception as e:
        print("Incorrect decryption:", e)
        tempFile = os.listdir("temp")[0]
        shutil.copy(os.path.join("temp", tempFile), "decrypted_img" + tempFile[tempFile.rfind("."):])
        shutil.rmtree("temp")

    song.close()  

#Analyse Audio
def analyseAudio():
    subprocess.call(["python" , "Sound Secret/Analyse.py"])

def analyseAudio_script():
    thread = threading.Thread(target=analyseAudio)
    thread.start()

#RSA 
def newkeys():
    subprocess.call(["python", "Sound Secret/rsa.py"])

def newkeys_script():
    thread = threading.Thread(target=newkeys)
    thread.start()




if __name__ == "__main__":
    app = App()
    app.mainloop()