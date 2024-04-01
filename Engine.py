import os  # using to generate salt value
from cryptography.fernet import Fernet  # symmetric key encryption
from cryptography.hazmat.primitives.asymmetric import rsa  # asymmetric key import
from cryptography.hazmat.primitives import hashes  # using this to create MD5 hash
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import InvalidToken
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# https://cryptography.io/en/latest/
# pip install cryptography


"""
Steps:
1. Generate a symmetric-key(symmetric-key-filename) and save to a file. Will be bound to create-symmetric-key command --- COMPLETED
2. Generate an asymmetric-key(public-key-filename private-key-filename) and save to a file. Will be bound to create-asymmetric-key command--- COMPLETED
3. Encrypt-Field(public-key-filename field-value) must output field-name=”encrypted-field-value” field-name is provided in command line.--- COMPLETED
4. Decrypt-Field(private-key-filename encrpyted-field-value symmetric-key-file) must output field-name=”decrypted-field-value” reverses step 3.--- COMPLETED
5. sign-field(field-name encrypted-field-value private-key-file-name) hash of encryped-field-value by SHA-1 or MD5 and creates a signature. passport.owner_name=“43fdfdfg23432efshrdfrte2egsdadaee242|fd3534s
jkkhukkhkhkhhu23422” --- COMPLETED
6.verify-field(field-name encrypted-field-name MAC public-key-filename) mac is digitally-signed version of hash, verifies file using public key producing an expected hash and comparing this to the hash.
Outputs: “Field field-name verified correctly!” OR “Field field-name COULD NOT be verified!”
7. Encrypt-File(public-key-filename file-name) encrypts the file using the public key and outputs the encrypted file.
8.Store-passport(passport-file-name encrypted-passport-file symmetrickey-file-name private-key-file-name) 
9. retrieve-passport(passport-file-name encrypted-passport-file symmetric-key-file-name public-key-file-name)
"""


class PassportEngine:
    def __init__(self):
        self.symmetric_key_filename = None
        self.public_key_filename = None
        self.private_key_filename = None

    def create_symmetric_key(self, sym_key_filename):
        # Generate a symmetric key and save it to a file
        self.symmetric_key_filename = sym_key_filename
        # TODO: Implement symmetric key generation and saving to a file
        key = Fernet.generate_key()
        with open(self.symmetric_key_filename, "wb") as f:
            f.write(key)
        f.close()

    def create_asymmetric_key(self, priv_key_filename, pub_key_filename):
        # Generate an asymmetric key pair and save them to files
        self.public_key_filename = pub_key_filename
        self.private_key_filename = priv_key_filename
        # TODO: Implement asymmetric key generation and saving to files
        # KEY GENERATION
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        # KEY SAVING
        with open(self.public_key_filename, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        f.close()
        with open(self.private_key_filename, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        f.close()

    def encrypt_field(self, field_name, field_value, symmetric_key_file):
        # Encrypt the field value using the public key
        encrypted_field_value = ""
        # TODO: Implement field encryption using the public key
        # Salt value for fieldname
        salt = os.urandom(4)  # 4 bytes salt value

        formatted_prencrypted_field_value = f"{field_value}|{salt}"

        # load key
        with open(symmetric_key_file, "rb") as f:
            symmetric_key = f.read()
        f.close()
        encoder = Fernet(symmetric_key)
        encrypted_field_value = encoder.encrypt(
            formatted_prencrypted_field_value.encode("UTF-8")
        )

        encrypted_field_value_str = encrypted_field_value.decode("UTF-8")
        return encrypted_field_value_str

    def decrypt_field(self, field_name, encrypted_field_value, symmetric_key_file):

        try:
            with open(symmetric_key_file, "rb") as f:
                symmetric_key = f.read()
            f.close()
            fernet = Fernet(symmetric_key)
            decrypted_data = fernet.decrypt(
                encrypted_field_value.encode("UTF-8")
            ).decode()
            field_value = decrypted_data.split("|")[0]
            return field_value
        except InvalidToken:
            print("Invalid token. Cannot decrypt.")

    def sign_field(self, field_name, encrypted_field_value, private_key_filename):
        # Create a signature for the encrypted field value using the private key
        digest = hashes.Hash(hashes.MD5(), backend=default_backend())
        encrypted_field_value = encrypted_field_value.encode("UTF-8")
        digest.update(encrypted_field_value)
        mac_value = digest.finalize()

        # loading private key
        with open(private_key_filename, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )

        # Sign the hash using the private RSA key
        mac = private_key.sign(
            mac_value,
            padding.PSS(
                mgf=padding.MGF1(hashes.MD5()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.MD5(),
        )

        # Encode the signature for safe storage or transmission
        mac_encoded = base64.urlsafe_b64encode(mac).decode("UTF-8")
        encrypted_field_value_str = encrypted_field_value.decode("UTF-8")
        # Concatenate the encrypted field value and the signature
        signed_field = f"{encrypted_field_value_str}|{mac_encoded}"

        return signed_field

    def verify_field(self, field_name, encrypted_field_value, mac, public_key_filename):

        # TODO: Implement field verification using the MAC and public key
        # decrypting and seperating the mac and the encrypted field value
        with open(public_key_filename, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(), backend=default_backend()
            )

        mac = base64.urlsafe_b64decode(mac)

        # Create a hash (digest) of the encrypted field value
        digest = hashes.Hash(hashes.MD5(), backend=default_backend())
        encrypted_field_value_bytes = encrypted_field_value.encode("UTF-8")
        digest.update(encrypted_field_value_bytes)
        hash_value = digest.finalize()

        # Verify the signature
        try:
            public_key.verify(
                mac,
                hash_value,
                padding.PSS(
                    mgf=padding.MGF1(hashes.MD5()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.MD5(),
            )
            verification_result = True
        except Exception as e:  # Catching broad exception to simplify
            verification_result = False

        return verification_result

    def store_passport(
        self,
        passport_file_name,
        encrypted_passport_file,
        symmetric_key_file_name,
        private_key_file_name,
    ):
        encrypted_and_signed_data = ""

        # Read the passport file content as text, assuming each line is a field
        with open(passport_file_name, "r") as file:
            lines = file.readlines()

        # Process each line: encrypt the field, sign it, and append it to the output string
        for line in lines:
            if "=" in line:  # Simple check to ensure the line is valid for processing
                field_name, field_value = line.strip().split("=", 1)
                # Encrypt the field value
                encrypted_field_value = self.encrypt_field(
                    field_name, field_value, symmetric_key_file_name
                )
                # Sign the encrypted field value
                signed_field_value = self.sign_field(
                    field_name, encrypted_field_value, private_key_file_name
                )
                # Append this field's encrypted and signed data to the overall data string
                encrypted_and_signed_data += f"{field_name}={signed_field_value}\n"

        # Write the encrypted and signed data to the specified file
        with open(encrypted_passport_file, "w") as file:
            file.write(encrypted_and_signed_data)

        print(f"Passport data stored in '{encrypted_passport_file}'.")

    # def retrieve_passport(self, passport_file_name, encrypted_passport_file, symmetric_key_file_name, public_key_file_name):
    # Retrieve the passport information from files
    # TODO: Implement passport retrieval

    def retrieve_passport(
        self,
        passport_file_name,
        encrypted_passport_file,
        symmetric_key_file_name,
        public_key_file_name,
    ):
        result_data = ""
        verification_failed = False

        with open(encrypted_passport_file, "r") as file:
            lines = file.readlines()

        for line in lines:
            if "=" in line and "|" in line:
                field_name, rest = line.strip().split("=", 1)
                encrypted_field_value, mac = rest.split("|", 1)
                encrypted_field_value = encrypted_field_value.strip()
                mac = mac.strip()

                # Verify the field's signature
                if self.verify_field(
                    field_name, encrypted_field_value, mac, public_key_file_name
                ):
                    # Decrypt the field upon successful verification
                    decrypted_value = self.decrypt_field(
                        field_name, encrypted_field_value, symmetric_key_file_name
                    )
                    result_data += f"{field_name}={decrypted_value}\n"
                else:
                    print(f"Verification failed for field: {field_name}")
                    verification_failed = True
                    break

        # Write the decrypted data to the passport file only if all verifications succeed
        if not verification_failed:
            with open(passport_file_name, "w") as file:
                file.write(result_data)
        else:
            print(
                "Error: Some fields failed verification. No data written to passport file."
            )
