import os
import sys
import zipfile
import urllib.request

DEST_DIR = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Git")
ZIP_PATH = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "mingit.zip")

# MinGit 64-bit release from Git for Windows
MINGIT_URL = "https://github.com/git-for-windows/git/releases/download/v2.44.0.windows.1/MinGit-2.44.0-64-bit.zip"

print(f"Downloading MinGit to: {ZIP_PATH}...")
os.makedirs(os.path.dirname(DEST_DIR), exist_ok=True)
urllib.request.urlretrieve(MINGIT_URL, ZIP_PATH)

print(f"Extracting MinGit into: {DEST_DIR}...")
os.makedirs(DEST_DIR, exist_ok=True)
with zipfile.ZipFile(ZIP_PATH, 'r') as zip_ref:
    zip_ref.extractall(DEST_DIR)

if os.path.exists(ZIP_PATH):
    os.remove(ZIP_PATH)

git_cmd = os.path.join(DEST_DIR, "cmd", "git.exe")
if os.path.exists(git_cmd):
    print(f"SUCCESS: MinGit installed at: {git_cmd}")
else:
    print("Warning: Git executable not found in destination.")
