#!/bin/bash

git restore .
git pull 

echo "🚀 Starting application"
uvicorn app:app --host 127.0.0.1 --port 9000