# docker build

docker build -t firewall-app .

# docker run

docker run --rm -it \
  --name firewall-app \
  --privileged \
  --cap-add=NET_ADMIN \
  --network=host \
  -v "$(pwd)/firewall_rules.json:/app/firewall_rules.json" \
  -v "$(pwd):/app" \
  firewall-app

# usage

localhost:5000

# UWAGAGAGAGAGA

mozna sobie rozwalic system uzywac z rozwagą
