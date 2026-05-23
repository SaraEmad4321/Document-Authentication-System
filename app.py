from flask import Flask, render_template, request, jsonify #Flask: is the main framework to build the web app ; render_template: is used to load the html file; request: used to access incoming data e.g. form data, files, json files; jsonify: used to return json responses
from werkzeug.utils import secure_filename #secure_filename: prevents unsafe file names
import base64 #base64: used to convert binary data(signature) into text, so it could be stored in the json file
import os #os: used for file & directory operations (paths, folders)
import json #json: used to store & read data(keys & signatures) in json format
from cryptography.hazmat.primitives import hashes, serialization #hashes: provides hashing algorithms including the SHA256; serialization: used to convert keys to or form text format (PEM)
from cryptography.hazmat.primitives.asymmetric import ec # ec: used for Elliptic Cure Cryptography
from cryptography.exceptions import InvalidSignature #exception raised when signature verification fails
from datetime import datetime, timedelta # used to record the time when a file is signed
import logging #used to log everything user does

app = Flask(__name__) #Create the flask application

UPLOAD_FOLDER = "uploads" #define folder(uploads: to save the uploaded files with it's metadata in json file; keys: used to store user's key pairs)
KEYS_FOLDER = "keys"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER # configure flask to use the uploads folder

os.makedirs(UPLOAD_FOLDER, exist_ok=True) # create folders if they don't exist otherwise prevent error is they already exists
os.makedirs(KEYS_FOLDER, exist_ok=True)


audit_logger = logging.getLogger('security_auditor') #create and set a security logger
audit_logger.setLevel(logging.INFO)
#create a file handler to save in logs.log, mode overwrite so it adds new logs each time we run 
file_handler = logging.FileHandler('logs.log', mode='w')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')) #create and set the formatter
audit_logger.addHandler(file_handler)

def key_path(username): 
    return os.path.join(KEYS_FOLDER, f"{username}.json") #returns the file path for a user's keys e.g. keys/user1.json

def save_keypair(username, private_key):
    priv_pem = private_key.private_bytes( #convert private key to PEM format(text), so it can be saved
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    pub_pem = private_key.public_key().public_bytes( # here it convert the public key to text format
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    with open(key_path(username), "w") as f:
        json.dump({"private": priv_pem, "public": pub_pem}, f, indent=4) #Save both keys in a json file per user

def load_keypair(username):
    path = key_path(username)
    if not os.path.exists(path): #If user doesn't exist, return nothing
        return None
    with open(path, "r") as f:
        data = json.load(f) #otherwise load key data from the json file normally
    private_key = serialization.load_pem_private_key( #convert PEM text back into usable key objects
        data["private"].encode(), password=None
    )
    public_key = serialization.load_pem_public_key(data["public"].encode())
    return {"private": private_key, "public": public_key} #return keys as a dictionary

def user_exists(username): #Check if the user already has a saved key file or not
    return os.path.exists(key_path(username))

def get_all_users(): #Loop through all key files in the folder (Key_folder)
    users = []
    for fname in os.listdir(KEYS_FOLDER):
        if fname.endswith(".json"):
            users.append(fname[:-5]) #extract username (remove .json extension)
    return sorted(users)

def default_users(): #create default users if they don't exist
    for name in ["user1", "user2"]:
        if not user_exists(name):
            pk = ec.generate_private_key(ec.SECP256R1()) #Generate a new ECC private key using SECP256R1 curve
            save_keypair(name, pk) #saves the generated key pair

default_users() #runs this function when app starts

#-----------------Signing function-----------------
def sign_data(private_key, data): 
    return private_key.sign(data, ec.ECDSA(hashes.SHA256())) #Sign data using: ECDSA algorithm & SHA-256 hashing

#-----------------Routes-----------------
@app.route("/")
def index():
    return render_template("index.html", message="") #load homepage with an empty message

#-----------------List User-----------------
@app.route("/users", methods=["GET"])
def list_users():
    return jsonify(get_all_users()) #return all usernames as json

#-----------------Register-----------------
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() #Get json data sent from frontend
    username = (data.get("username") or "").strip().lower() #remove spaces from the username and convert it to lowercase
#-----------------Input Validation-----------------
    if not username:
        return jsonify({"ok": False, "message": "Username cannot be empty."}) #Reject empty username
    if len(username) < 3:
        return jsonify({"ok": False, "message": "Username must be at least 3 characters."}) #Ensure minimum length
    if not username.replace("_", "").replace("-", "").isalnum():
        return jsonify({"ok": False, "message": "Username may only contain letters, numbers, hyphens, and underscores."}) #Allows only letters a-z, numbers 0-9, underscores '_', and hyphens '-'
    if user_exists(username):
        return jsonify({"ok": False, "message": f"Username '{username}' is already taken."}) #prevent duplicate usernames

    private_key = ec.generate_private_key(ec.SECP256R1()) # Generate & save a new key pair for the user
    save_keypair(username, private_key)
    return jsonify({"ok": True, "message": f"Account created for '{username}'. ECDSA key pair generated and saved."})
#-----------------Sign File-----------------
@app.route("/sign", methods=["POST"])
def sign():
    file = request.files.get("file") #get uploades file & signer username
    signer = request.form.get("signer")

    if not file or file.filename == "":
        audit_logger.warning(f"SIGNATURE FAIL: Attempted By User: {signer} - No File Selected") #log warning in logs.log
        return render_template("index.html", message="No file selected") #when no files selected
    if not user_exists(signer):
        audit_logger.warning(f"SIGNATURE FAIL: Attempted By User: {signer} - Invaild User") #log warning in logs.log
        return render_template("index.html", message="Invalid signer") #when user doesn't exist 


    filename = secure_filename(file.filename) #for secure file naming
    data = file.read() # Read file directly 
    file_content = base64.b64encode(data).decode() # Convert to Base64 (best for other file format like images or pdfs)

    keypair = load_keypair(signer)
    signature = sign_data(keypair["private"], data) #Generate digital signature using private key
    expiry = datetime.now() + timedelta(days=30) #set expiration so the signature will expire in 1 month from now

    sig_data = {
        "filename": filename,
        "file_content": file_content,
        "signer": signer,
        "hash_algorithm": "SHA-256",
        "signature_algorithm": "ECDSA-SECP256R1",
        "signature": base64.b64encode(signature).decode(), #Convert signature from binary to text for storage
        "timestamp": datetime.now().isoformat(),
        "expires_at": expiry.isoformat()
    }
    sig_filename = filename + ".sig.json"
    sig_path = os.path.join(app.config["UPLOAD_FOLDER"], sig_filename)   #signature file path (filename.extension.sig.json)
    with open(sig_path, "w") as f:
        json.dump(sig_data, f, indent=4) #save signature metadata in json file

    audit_logger.info(f"SIGNATURE SUCCESS: Created By User: {signer}, Signed File: {filename}") #log info in logs.log
    return render_template("index.html", message=f" File signed by {signer}")
#-----------------Verify-----------------
@app.route("/verify", methods=["POST"])
def verify():
    file = request.files.get("file")
    verify_user = request.form.get("verify_user")
    if not file or file.filename == "":
        audit_logger.warning(f"VERIFICATION FAIL: Attempted By User: {signer} - No File Selected") #log warning in logs.log
        return render_template("index.html", message="No file selected")
    if not user_exists(verify_user):
        audit_logger.warning(f"VERIFICATION FAIL: Attempted By User: {signer} - Invaild User") #log warning in logs.log
        return render_template("index.html", message="Invalid verification user")

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    sig_path = filepath + ".sig.json" #locate corresponding signature file
    if not os.path.exists(sig_path):
        audit_logger.warning(f"VERIFICATION FAIL:  Attempted By User: {signer} - Signature File Not Found") #log warning in logs.log
        return render_template("index.html", message="Signature file not found — sign the document first")

    with open(sig_path, "r") as f:
        sig_data = json.load(f) #Load signature data

    signer = sig_data.get("signer") #Extract original signer
    expiry_date = datetime.fromisoformat(sig_data.get("expires_at")) #extract expiration date

    if datetime.now() > expiry_date: #check the expiration
        audit_logger.error(f"VERIFICATION FAIL:  Attempted By User: {signer} - Signature Expired")
        return render_template("index.html", message=f"Signature expired - on {expiry_date}")
    
    try:
        with open(filepath, "rb") as f:
            data = f.read()

        if verify_user != signer: #Check if wrong public key is used (Test Case 3)
            audit_logger.error(f"VERIFICATION FAIL:  Attempted By User: {signer} - Used Wrong Public Key") #log error in logs.log
            return render_template("index.html", message=f"Wrong public key — signed by {signer}, verified as {verify_user}")

        signature = base64.b64decode(sig_data["signature"]) #Convert signature back to binary
        keypair = load_keypair(verify_user)
        keypair["public"].verify(signature, data, ec.ECDSA(hashes.SHA256())) #Verify signature using public key
        audit_logger.info(f"VERIFICATION SUCCESS: Attempted By User: {signer}") #log info in logs.log
        return render_template("index.html", message=f" AUTHENTIC — ECDSA signature valid (signed by {signer})") #Test Case 1:Valid Signature

    except InvalidSignature:
        audit_logger.error(f"VERIFICATION FAIL: Attempted By User: {signer} - Document Tampered Or Signature Corrupted") #log error in logs.log
        return render_template("index.html", message="INVALID — Document tampered or signature corrupted") #Test Case2&4 Document/Signature Tampering
    except Exception as e:
        audit_logger.error(f"UNEXPECTED ERROR OCCURRED") #log error in logs.log
        return render_template("index.html", message=f"Unexpected error: {str(e)}")

if __name__ == "__main__": # Start the flask server
    open('logs.log', 'w').close() #opens log file and immediately closes it, so it clears the content
    app.run(debug=True) #debug=True enables auto-reload & error messages 