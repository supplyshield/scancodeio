#!/bin/sh

./manage.py migrate && \
./manage.py collectstatic --no-input --verbosity 0 --clear && \
gunicorn scancodeio.wsgi:application --bind :8000 --timeout 1800 --workers 8
