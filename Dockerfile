FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Copy all SIEM modules and requirements.txt into the container
COPY . /app

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Default command to run your SIEM main script
CMD ["python", "hello.py"]