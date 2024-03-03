FROM python:3.11

RUN apt-get update && apt-get install -y netcat-openbsd && rm -rf /var/lib/apt/lists/*

# Create a non-root user and switch to it
RUN adduser --disabled-password --gecos '' appuser

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the application code into the container
COPY . .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Add local user bin directory to PATH
ENV PATH="/home/appuser/.local/bin:${PATH}"

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Use Entrypoint for shells

ENTRYPOINT ["./entry.sh"]
