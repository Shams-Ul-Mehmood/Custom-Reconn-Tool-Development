# Use a lightweight Python base image
FROM python:3.11-slim

# Install Nmap for the active port scanning backend
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

# Set the working directory to match the volume mount paths in the report
WORKDIR /app

# Copy requirements first to leverage Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the core project files into the container
COPY main.py .
COPY modules/ modules/
COPY utils/ utils/

# Create the reports directory so the container has a target for output
RUN mkdir -p reports

# Set the default executable to main.py
ENTRYPOINT ["python3", "main.py"]
