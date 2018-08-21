import ipaddress
import time

import requests
from prometheus_client.parser import text_string_to_metric_families
from pytest_docker_tools import build, container

tshark_exporter_image = build(path='.')

tshark_exporter = container(
    image='{tshark_exporter_image.id}',
    ports={
        '9431/tcp': None,
    },
)


def test_metrics_server_responds_immediately(tshark_exporter):
    port = tshark_exporter.ports['9431/tcp'][0]
    response = requests.get(f'http://localhost:{port}/metrics')
    assert response.status_code == 200
    assert b'# HELP tshark_exporter_match_bytes' in response.content
    assert b'# HELP tshark_exporter_match_count' in response.content


def test_simple_capture(tshark_exporter):
    port = tshark_exporter.ports['9431/tcp'][0]

    while 'Capturing on \'eth0\'' not in tshark_exporter.logs():
        time.sleep(0.5)

    response = requests.get(f'http://localhost:{port}/metrics')
    assert response.status_code == 200

    while b'tshark_exporter_match_bytes{' not in response.content:
        time.sleep(0.5)
        response = requests.get(f'http://localhost:{port}/metrics')
        assert response.status_code == 200

    metrics = {mf.name: mf for mf in text_string_to_metric_families(response.text)}

    # We should have metrics for the inward and outward ends of the TCP stream
    assert len(metrics['tshark_exporter_match_bytes'].samples) == 2
    assert len(metrics['tshark_exporter_match_count'].samples) == 2

    inbound, outbound = list(sorted(metrics['tshark_exporter_match_bytes'].samples, key=lambda sample: sample[2]))

    # Should be able to provde that the streams are opposite of one another
    assert inbound[1]['ip_src'] == outbound[1]['ip_dst']
    assert inbound[1]['ip_dst'] == outbound[1]['ip_src']

    assert inbound[1]['asn_src'] == outbound[1]['asn_dst']
    assert inbound[1]['asn_dst'] == outbound[1]['asn_src']

    assert inbound[1]['mac_src'] == outbound[1]['mac_dst']
    assert inbound[1]['mac_dst'] == outbound[1]['mac_src']

    # All ip addresses should be valid
    ipaddress.ip_address(inbound[1]['ip_src'])
    ipaddress.ip_address(inbound[1]['ip_dst'])
