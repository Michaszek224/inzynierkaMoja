# docker build

docker build -t firewall-app .

# docker run

docker run \
    --name firewall-control \
    -p 5000:5000 \
    --cap-add=NET_ADMIN \
    -v "$(pwd)/firewall_rules.json":/app/firewall_rules.json \
    firewall-app