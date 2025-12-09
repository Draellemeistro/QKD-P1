# Docker Setup

## Running the Docker Setup

**Important:** All docker commands must be run from the `docker/` directory:

```bash
cd docker
docker-compose up
```

To access the nodes use:
docker-compose exec node-a bash
docker-compose exec node-b bash

Refer to QKD-net readme for further instructions on how to use the QKD simulator. 



## Submodule Setup

QKD-net is a git submodules. After cloning the repository, you need to initialize and update it:

```bash
# 1. Initialize the submodule (reads the .gitmodules file)
git submodule init

# 2. Update the submodule (fetches the content for the correct commit)
git submodule update
```


