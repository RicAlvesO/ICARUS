# Makefile for managing Docker Compose services
.PHONY: start logs stop status down rebuild setup shell exec

# Variables:
# NONE

# Start the services in detached mode
start:
	@echo "Starting Docker Compose services..."
	docker compose up --build -d
	@ansible-playbook -i hosts ./playbooks/setup.yml

# View logs for all services
logs:
	@echo "Viewing logs for all services..."
	docker compose logs

# Stop the services
stop:
	@echo "Stopping Docker Compose services..."
	docker compose stop

# Check the status of the services
status:
	@echo "----------------------------------------------"
	@echo "Checking status of Docker Compose services..."
	@echo "----------------------------------------------"
	@echo ""
	@docker compose ps
	@echo ""
	@echo "----------------------------------------------"
	@echo "Summary of service status:"
	@echo "----------------------------------------------"
	@echo ""
	@docker compose top
	@echo ""
	@echo "----------------------------------------------"
	@echo "Resource usage for services:"
	@echo "----------------------------------------------"
	@echo ""
	@docker stats --no-stream 
	@echo ""

# Stop and remove the services
down:
	@echo "Stopping and removing Docker Compose services..."
	docker compose down

# Remove all unused images, networks, and volumes
clean:
	@echo "Cleaning up unused Docker resources..."
	docker system prune -a --volumes -f
	docker image prune -a -f
	docker volume prune -f
	docker network prune -f
	docker container prune -f
	@echo "Cleanup complete."

# Rebuild and restart the services
rebuild: down start
	@echo "Rebuilding and restarting Docker Compose services..."

# Setup the whole environment
setup: down
	@echo "Setting up the entire environment..."
	docker compose up --build --force-recreate -d 
	@ansible-playbook -i ./playbooks/hosts ./playbooks/setup.yml

# Open a terminal shell/run a command in the specified host container with reconnection logic
shell:
	@echo "Opening terminal in the $(host) container..."
	@retries=0; \
	max_retries=3; \
	until docker exec -it proofofconcept-$(host)-1 /bin/zsh -c '${command}'; do \
		retries=$$((retries+1)); \
		if [ $$retries -ge $$max_retries ]; then \
			echo "Failed after $$max_retries attempts. Exiting."; \
			exit 1; \
		fi; \
		echo "Disconnected from $(host) container. Attempting to reconnect in 30 seconds... (attempt $$retries of $$max_retries)"; \
		sleep 30; \
	done

# Stop the specified host container
sstop:
	@echo "Stopping the $(host) container..."
	docker stop  proofofconcept-$(host)-1
