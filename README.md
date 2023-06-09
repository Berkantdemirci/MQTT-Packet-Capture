# MQTT-Packet-Capture

## Preliminary

You need to install libpcap library to be able to use the project.

```sh
sudo apt-get install git libpcap-dev
pip3 install paho-mqtt
```

## Compile & Run

Just run the "compile.sh" bash script to compile. The binary named "mqtt_listen" must be created.

!!!ATTENTION!!!

This project only runs under root privileges. 

AUTHORS 

- Hüseyin Yüce
- Berkant Demirci

Resources 

- https://devnot.com/2017/mqtt-nedir-nasil-bir-mimaride-calisir/
- https://www.tcpdump.org/pcap.html
- https://www.devdungeon.com/content/using-libpcap-c
- https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/
- https://openlabpro.com/guide/mqtt-packet-format/
- https://www.emqx.com/en/blog/how-to-use-mqtt-in-python
- http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html