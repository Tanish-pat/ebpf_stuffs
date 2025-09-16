#!/bin/sh

# Default commit message
DEFAULT_MSG="pushed updates"

# Use provided message or default
MSG="${1:-$DEFAULT_MSG}"

git add .
git commit -m "$MSG"
git push -u origin main