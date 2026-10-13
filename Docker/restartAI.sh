clear

python3 update_readme.py

echo -e "\n=== Close Container  ==="
docker compose down ai_agent

echo -e "\n=== Start Container  ==="
docker compose up -d ai_agent

echo -e "\n=== Observe AI Agent ==="
docker logs -f ai_agent