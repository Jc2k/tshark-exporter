FROM alpine:3.8

ENV PYTHONUNBUFFERED 1

RUN apk --no-cache add tshark python3

COPY requirements.txt /requirements.txt
RUN python3 -m pip install -r /requirements.txt

COPY exporter.py /usr/bin/tshark-exporter

STOPSIGNAL SIGINT

CMD /usr/bin/tshark-exporter
