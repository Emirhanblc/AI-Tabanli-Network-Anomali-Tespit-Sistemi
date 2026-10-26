import os

os.environ["DATABASE_URL"] = "sqlite:///./test_ids.db"
os.environ["MODEL_PATH"] = "artifacts/test-missing-model.pkl"
