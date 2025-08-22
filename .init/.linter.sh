#!/bin/bash
cd /home/kavia/workspace/code-generation/food-inventory-management-system-162759-162768/food_management_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

