#!/bin/bash

RUN_BUILD=false
COMMIT_MSG=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --build)
      RUN_BUILD=true
      shift
      ;;
    *)
      COMMIT_MSG="$COMMIT_MSG $1"
      shift
      ;;
  esac
done

COMMIT_MSG="${COMMIT_MSG:-Update}"
COMMIT_MSG=$(echo "$COMMIT_MSG" | xargs)

echo "➡️ Commit message: \"$COMMIT_MSG\""

git add .
git commit -m "$COMMIT_MSG"
git push -u origin main

echo "✅ Pushed!"