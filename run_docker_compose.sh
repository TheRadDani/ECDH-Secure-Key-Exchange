# Stop containers
docker-compose down

# Remove the problematic network
docker network rm cryptoexhange_crypto-network

# Bring everything back up
docker-compose --env-file .env up
