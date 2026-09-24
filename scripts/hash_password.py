from getpass import getpass

from pwdlib import PasswordHash


def main() -> None:
    password = getpass("Contraseña: ")
    confirmation = getpass("Repetir contraseña: ")
    if password != confirmation:
        raise SystemExit("Las contraseñas no coinciden")
    if len(password) < 12:
        raise SystemExit("La contraseña debe tener al menos 12 caracteres")
    print(PasswordHash.recommended().hash(password))


if __name__ == "__main__":
    main()
