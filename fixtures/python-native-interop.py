import base64
import json
import subprocess

from porter.native import open_frame, public_key, seal


def run(*arguments):
    return subprocess.check_output(
        ["/usr/local/bin/native_fixture", *arguments], text=True
    ).strip()


sender_private = base64.b64encode(bytes([7]) * 32).decode()
recipient_private = base64.b64encode(bytes([11]) * 32).decode()
sender_public = public_key(sender_private)
recipient_public = public_key(recipient_private)
value = {"opaque": {"language": "irrelevant"}}

rust_frame = base64.b64decode(
    run(
        "seal",
        "sender",
        sender_private,
        "recipient",
        recipient_public,
        "PACKAGE",
        "CU-rust-to-python",
        json.dumps(value, separators=(",", ":")),
    )
)
rust_envelope, rust_value = open_frame(
    rust_frame[9:], "recipient", recipient_private, {"sender": sender_public}
)
assert rust_envelope["unit"] == "CU-rust-to-python"
assert rust_value == value

python_frame = seal(
    value,
    "sender",
    sender_private,
    "recipient",
    recipient_public,
    "CEREMONY_RESULT",
    "CU-python-to-rust",
)
opened = json.loads(
    run(
        "open",
        "recipient",
        recipient_private,
        "sender",
        sender_public,
        base64.b64encode(python_frame).decode(),
    )
)
assert opened == value
print("Python ↔ Rust protected native carriage: PASS")
