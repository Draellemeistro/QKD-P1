# Docker Setup

## Running the Docker Setup

**Important:** All docker commands must be run from the `docker/` directory:

```bash
cd docker
docker-compose up
```

## Submodule Setup

This project uses git submodules. After cloning the repository, you need to initialize and update the submodules:

```bash
# 1. Initialize the submodule (reads the .gitmodules file)
git submodule init

# 2. Update the submodule (fetches the content for the correct commit)
git submodule update
```

Alternatively, you can clone with submodules in one step:

```bash
git clone --recurse-submodules https://github.com/Draellemeistro/QKD-P1
```
