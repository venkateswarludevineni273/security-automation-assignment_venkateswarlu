import os

# config.py refuses to start without a strong signing key. Set a throwaway one
# before any test module imports the app.
os.environ.setdefault("SECRET_KEY", "test-only-signing-key-not-a-real-secret-0123456789")
