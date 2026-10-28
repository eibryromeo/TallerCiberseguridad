import hashlib

with open("archivo.txt", "rb") as f:
  content = f.read()

print(hashlib.sha256(content).hexdigest())