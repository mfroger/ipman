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

if [ "$RUN_BUILD" = true ]; then
  echo "✨ Formatting..."
  npm run format

  echo "🏗️ Running build..."
  npm run build

  if [ $? -ne 0 ]; then
    echo "❌ Build failed. Please fix errors and try again."
    exit 1
  fi
fi

echo "🧹 Cleaning..."
trash node_modules package-lock.json .next .turbo

echo "📦 Installing dependencies"
npm install

git add .
git commit -m "$COMMIT_MSG"
git push -u origin dev

echo "✅ Pushed!"

echo "🚀 Starting application frontend"
npm run dev