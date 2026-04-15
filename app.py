"""WSGI entrypoint for platforms that run `gunicorn app:app`."""

from backend.app import app
