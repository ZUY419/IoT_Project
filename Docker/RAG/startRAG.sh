docker compose down
docker system prune -f --volumes
docker compose build
docker compose up -d