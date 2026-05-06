import os

STORAGE_URL    = os.getenv("STORAGE_URL",    "")
BLOCKCHAIN_URL = os.getenv("BLOCKCHAIN_URL", "")
AI_URL         = os.getenv("AI_URL",         "")
SANDBOX_URL    = os.getenv("SANDBOX_URL",    "")
GATEWAY_PUBLIC_URL = os.getenv("GATEWAY_PUBLIC_URL")
REQUEST_TIMEOUT = 60

_SANDBOX_EXTENSIONS = {"sh", "bash", "zsh", "py", "pl", "jar"}
