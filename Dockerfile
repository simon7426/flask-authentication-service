FROM python:3.8.12-slim-buster

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV FLASK_ENV production
ENV SERVER_NO $SERVER_NO

RUN apt-get update \
  && apt-get -y install netcat \
  && apt-get clean

COPY ./requirements.txt .
RUN pip install -r requirements.txt

COPY . .

RUN adduser --disabled-password myuser
USER myuser

CMD gunicorn --workers 3 --bind 0.0.0.0:$PORT manage:app