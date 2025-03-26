FROM python:3.9-slim

RUN apt-get update && apt-get install -y default-jre  


WORKDIR /app

COPY backend/ ./backend/
RUN pip install -r backend/requirements.txt


COPY frontend/build/ ./frontend/build/


COPY backend/tools/ ./backend/tools/

EXPOSE 5000


WORKDIR /app/backend


CMD ["python", "app.py"]