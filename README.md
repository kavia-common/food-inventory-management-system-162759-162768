# food-inventory-management-system-162759-162768

Backend: FastAPI service exposing authentication, food inventory CRUD, notifications, and reporting.

How to run (local):
- Create and set environment variables based on food_management_backend/.env.example
- Install dependencies: pip install -r food_management_backend/requirements.txt
- Start server: uvicorn food_management_backend.src.api.main:app --reload --host 0.0.0.0 --port 8000

Docs: http://localhost:8000/docs