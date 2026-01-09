FROM python:3.10.17-slim

# Set up the app directory
RUN mkdir /app
WORKDIR /app
 
# Set environment variables 
# Prevent Python from writing pyc files to disk
ENV PYTHONDONTWRITEBYTECODE=1
#Prevent Python from buffering stdout and stderr
ENV PYTHONUNBUFFERED=1 

RUN pip install --upgrade pip 
 
# Copy the Django project  and install dependencies
COPY requirements.txt  /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/
 
# Run Django’s development server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]