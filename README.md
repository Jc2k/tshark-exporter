# tshark-exporter

Quick and dirty prometheus exporter for observing traffic in prometheus.

This is not meant to be ROFL-scale. This is not meant for putting *all* your traffic in Prometheus. The idea is you need to quickly deploy a sensor that matches known bad traffic so you can observe it over time. For example you, you want to target all traffic involving a particular ip:

```
docker run --rm -it -p 9431:9431 jc2k/tshark-exporter /usr/bin/tshark-exporter host 172.17.0.3
```

Or if you want to see TCP retransmissions:

```
docker run --rm -it -p 9431:9431 jc2k/tshark-exporter /usr/bin/tshark-exporter -Y tcp.analysis.retransmission
```
