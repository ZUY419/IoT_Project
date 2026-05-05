echo -e "強制移除「所有」Docker 殘留物 (大掃除)"
docker rm -f $(docker ps -aq) 2>/dev/null
docker network prune -f

bash opiotsys.sh