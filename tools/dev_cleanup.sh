#!/bin/bash

# Navigate to the project root directory regardless of where the script is called from
cd "$(dirname "$0")/.." || exit

echo "================================================================="
echo "                        WARNING                                  "
echo " This script is intended for DEVELOPERS ONLY. It will completely "
echo " wipe all local databases and telemetry data, and tear down the  "
echo " Docker Compose stack. This action CANNOT be undone!             "
echo "================================================================="

read -p "Are you sure you want to completely destroy all local data? (y/N) " -n 1 -r
echo    # move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
    echo "Stopping and removing containers..."
    docker compose down

    echo "Cleaning up local data directories..."
    # We use sudo here because docker containers often write files as root
    sudo rm -rf ./vm-data/* ./kuzu-data/* ./chroma-data/* ./collected_facts/*

    echo "Cleanup complete! The environment is pristine."
else
    echo "Cleanup aborted."
fi
