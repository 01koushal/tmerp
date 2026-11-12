import hashlib, json, os, uuid
from pathlib import Path
from cryptography.fernet import Fernet

CHUNK_SIZE = 1024 * 1024  # 1 MiB

def get_fernet(key_text):
    if not key_text:
        raise RuntimeError("EVIDENCE_MASTER_KEY is missing. Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"")
    return Fernet(key_text.encode() if isinstance(key_text, str) else key_text)

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def merkle_root(hex_hashes):
    if not hex_hashes:
        return sha256(b"")
    level = [bytes.fromhex(x) for x in hex_hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i+1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0].hex()

def seal_upload(file_storage, upload_folder, master_key):
    fernet = get_fernet(master_key)
    evidence_id = uuid.uuid4().hex
    folder = Path(upload_folder) / evidence_id
    folder.mkdir(parents=True, exist_ok=True)
    part_hashes, encrypted_paths, total = [], [], 0
    index = 0
    while True:
        chunk = file_storage.stream.read(CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        digest = sha256(chunk)
        encrypted = fernet.encrypt(chunk)
        path = folder / f"part-{index:05d}.enc"
        path.write_bytes(encrypted)
        part_hashes.append(digest)
        encrypted_paths.append(str(path))
        index += 1
    if not part_hashes:
        raise ValueError("The uploaded file is empty.")
    return evidence_id, total, part_hashes, merkle_root(part_hashes), encrypted_paths

def decrypt_parts(evidence, upload_folder, master_key):
    fernet = get_fernet(master_key)
    folder = Path(upload_folder) / evidence.storage_id
    for index, expected in enumerate(evidence.part_hashes):
        path = folder / f"part-{index:05d}.enc"
        if not path.exists():
            raise FileNotFoundError(f"Missing encrypted part {index}")
        plain = fernet.decrypt(path.read_bytes())
        if sha256(plain) != expected:
            raise ValueError(f"Integrity check failed for part {index}")
        yield plain

def verify_evidence(evidence, upload_folder, master_key):
    hashes = []
    try:
        for part in decrypt_parts(evidence, upload_folder, master_key):
            hashes.append(sha256(part))
        return hashes == evidence.part_hashes and merkle_root(hashes) == evidence.merkle_root
    except Exception:
        return False
