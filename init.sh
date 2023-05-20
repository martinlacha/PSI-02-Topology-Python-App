#!/bin/bash

# Update package repositories
apt-get update

# Install Git
apt-get install -y git

# Create the "mlacha" directory and navigate into it
mkdir /home/mlacha

# Change to the /home directory
cd /home/mlacha

# Clone the repository from GitHub
git clone https://github.com/martinlacha/PSI-02-Topology-Python-App.git

# Enter the cloned repository directory and enter src directory
cd PSI-02-Topology-Python-App/src

# Install pip
apt-get install -y pip

# Install necessary libraries from file requirements.txt
pip install -r requirements.txt