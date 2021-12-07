#!/bin/bash

while ! nc -z localhost 5432; do
    sleep 0.1
done

echo "PostgreSQL started"

python manage.py run -h 127.0.0.1 -p 8000