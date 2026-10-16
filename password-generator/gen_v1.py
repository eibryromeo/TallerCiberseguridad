import secrets
import string

alphabet = string.ascii_letters + string.digits + "!@#$%^&*"


def generate_password(length):
    return "".join(secrets.choice(alphabet) for _ in range(length))


print(generate_password(8))
print(generate_password(16))
print(generate_password(32))