# official image
FROM python:3.8.12-slim-buster

# working directory
WORKDIR /app

# environment variable
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install system dependencies
RUN apt-get update \
  && apt-get -y install netcat gcc postgresql \
  && apt-get clean


# install dependencies
RUN pip install --upgrade pip
COPY ./requirements.txt .
COPY ./requirements-dev.txt .
RUN pip install -r requirements-dev.txt

# add application
COPY . .

# add entrypoint.sh
COPY ./entrypoint.sh .
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT [ "./entrypoint.sh" ]
