ip link add dev veth0 type veth peer name veth1
ip link add dev veth2 type veth peer name veth3
ip link add dev veth4 type veth peer name veth5

simple_switch -i 0@veth0 -i 1@veth2 -i 2@veth4 --log-console inbandTelemetryBasic.json
