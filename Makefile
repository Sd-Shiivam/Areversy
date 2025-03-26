.PHONY: all build-frontend build-docker run clean

all: build-frontend build-docker run

build-frontend:
	@echo "Building React frontend..."
	cd frontend && npm install && npm run build

build-docker:
	@echo "Building Docker image..."
	docker-compose build

run:
	@echo "Running Docker container..."
	docker-compose up -d

clean:
	@echo "Cleaning up..."
	rm -rf backend/uploads/*
	rm -rf frontend/build/*
	docker-compose down
