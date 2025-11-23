# Firewall V.2.1

## docker build
```
docker build -t firewall-app .
```
## docker run
```
docker run --rm -it \
  --name firewall-app \
  --privileged \
  --cap-add=NET_ADMIN \
  --network=host \
  -v "$(pwd)/firewall_rules.json:/app/firewall_rules.json" \
  -v "$(pwd):/app" \
  firewall-app
```
## usage

localhost:5000

## UWAGAGAGAGAGA

mozna sobie rozwalic system uzywac z rozwagą

jesli ustawisz zle zasady i aplikacja nie dziala w przegladarce to skopiuj zasady z default i zapisz jako firewall_rules.json

np comenda

``` cp default_firewall_rules.json firewall_rules.json ```
