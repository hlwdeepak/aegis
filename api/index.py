import sys
import os
from pathlib import Path

# Ensure project root is in sys.path for Vercel Serverless environment
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

from aegis.server.app import app
