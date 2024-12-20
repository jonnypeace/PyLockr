FROM python:3.11

RUN apt-get update && apt-get upgrade -y && apt-get install -y netcat-openbsd && rm -rf /var/lib/apt/lists/*

# Create a non-root user and switch to it
RUN adduser --disabled-password --gecos '' --uid 1000 appuser

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the application code into the container
COPY . .
#COPY ./requirements.txt ./requirements.txt

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Use Entrypoint for shells

ENTRYPOINT ["./entry.sh"]
