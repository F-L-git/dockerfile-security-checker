FROM ubuntu:latest

RUN apt-get update
RUN apt-get install -y curl vim openssh-server

ENV DB_PASSWORD=supersecret123
ENV API_KEY=sk-1234567890abcdef

COPY . .

EXPOSE 22
EXPOSE 80

CMD python app.py
