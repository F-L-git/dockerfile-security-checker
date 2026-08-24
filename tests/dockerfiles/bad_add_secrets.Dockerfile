FROM python:3.12

WORKDIR /app

ADD requirements.txt .
ADD https://example.com/config.tar.gz /tmp/

RUN pip install -r requirements.txt

ARG SECRET_TOKEN=my-secret-token-value
ENV PASSWORD=$SECRET_TOKEN

COPY app.py .

USER root

CMD ["python", "app.py"]
