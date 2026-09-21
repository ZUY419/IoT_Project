clear

echo -e "\n=== Close Container  ==="
docker compose down ai_agent

echo -e "\n=== Start Container  ==="
docker compose up ai_agent -d

echo -e "\n=== Observe AI Agent ==="
docker logs -f ai_agent