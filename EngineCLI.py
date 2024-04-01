from Engine import PassportEngine
import shlex
import base64


def main():
    passport = PassportEngine()
    print("Welcome to the Vaccine Passport Management System.")
    while True:
        command = input("> ").strip()
        if not command:
            continue

        # Split the command into arguments

        args = shlex.split(command)

        # Check for the first argument (vaccinepassport)
        if args[0] != "vaccinepassport":
            print("Invalid command. Please start with 'vaccinepassport'.")
            continue

        # Process commands based on the second argument
        if args[1] == "create-symmetric-key":
            if len(args) != 3:
                print("Usage: vaccinepassport create-symmetric-key <filename>")

            else:
                print(f"Created symmetric key and saved to {args[2]}. (Simulated)")
                passport.create_symmetric_key(args[2])
        elif args[1] == "create-asymmetric-key":
            if len(args) != 4:
                pass
            else:
                print(f"Created asymmetric key and saved to {args[2]}. (Simulated)")
                passport.create_asymmetric_key(args[2], args[3])
        elif args[1] == "encrypt-field":
            if len(args) != 5:
                print(
                    "Usage: vaccinepassport encrypt-field <field_name> <field_value> <symmetric_key_filename>"
                )
            else:
                print(f"{args[2]}={passport.encrypt_field(args[2], args[3], args[4])}")
        elif args[1] == "decrypt-field":
            if len(args) != 5:
                print(
                    "Usage: vaccinepassport encrypt-field <field_name> <field_value> <symmetric_key_filename>"
                )
            else:
                print(f"{args[2]}= {passport.decrypt_field(args[2], args[3], args[4])}")

        elif args[1] == "sign-field":
            if len(args) != 5:
                print(
                    "Usage: vaccinepassport sign-field <field_name> <encrypted_field_value> <private_key_filename>"
                )
            else:
                print(f"{args[2]}= {passport.sign_field(args[2], args[3], args[4])}")
        elif args[1] == "verify-field":
            if len(args) != 6:
                print(
                    "Usage: vaccinepassport sign-field <field_name> <encrypted_field_value> <private_key_filename>"
                )
            else:
                if passport.verify_field(args[2], args[3], args[4], args[5]):
                    print(f"Field {args[2]} verified correctly!")
                else:
                    print(f"Field {args[2]} COULD NOT be verified!")
        elif args[1] == "store-passport":
            if len(args) != 6:
                print(
                    "Usage: vaccinepassport store-passport <passport_filename> <encrypted_passport_filename> <symmetric_key_filename> <private_key_filename>"
                )
            else:
                print(
                    f"Stored passport from {args[2]} to encrypted file {args[3]}. (Simulated)"
                )
                passport.store_passport(args[2], args[3], args[4], args[5])
        elif args[1] == "retrieve-passport":
            if len(args) != 6:
                print(
                    "Usage: vaccinepassport retrieve-passport <encrypted_passport_filename> <symmetric_key_filename> <private_key_filename> <public_key_filename>"
                )
            else:
                passport.retrieve_passport(args[2], args[3], args[4], args[5])


if __name__ == "__main__":
    main()
