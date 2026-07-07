FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Generate keys if not provided
RUN python -c "import os; os.environ['JWT_PRIVATE_KEY'] = '' if not os.environ.get('JWT_PRIVATE_KEY') else os.environ['JWT_PRIVATE_KEY']"

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
