---
title: ELK Stack Setup and Configuration Guide
---

# ELK Stack Setup and Configuration Guide

## Introduction

This document provides a detailed guide for deploying the **ELK Stack** — (Elasticsearch, Logstash, Kibana) — using **Docker Compose**.  
The ELK Stack is a powerful open-source platform for searching, analyzing, and visualizing log data in real-time.  

### Components
- **Elasticsearch**: A distributed search and analytics engine.
- **Logstash**: A server-side data processing pipeline that ingests data from multiple sources, transforms it, and sends it to a "stash" like Elasticsearch.
- **Kibana**: A visualization layer that works on top of Elasticsearch, providing users with tools to explore their data through charts, tables, and dashboards.

---

This guide prioritizes a secure-by-default setup, including the generation and use of passwords for all built-in users.

## Architecture Overview: Component Roles

This guide sets up a central ELK stack that can receive data from various sources, including both Windows and Ubuntu VMs.


  - **Elasticsearch and Kibana** are the core components and are **required for both Windows and Ubuntu**. They store, index, and visualize all incoming data.


  - **Logstash** is included in this stack specifically to serve as a data processor for log shippers like **Winlogbeat**, which is the method used for the **Windows VM setup**. Modern solutions like Elastic Agent (used for the Ubuntu VM) can send data directly to Elasticsearch, bypassing the need for a separate Logstash instance for that data path


## Prerequisites: Docker and Docker Compose Installation
Before you begin, you must have Docker Engine and Docker Compose installed on your system.

Please follow the official instructions to download and install both components for your specific operating system.

[Official Documentation](https://docs.docker.com/engine/install/)

## Project Structure
For a clean setup, organize your files in a root directory (e.g., my-elk-stack) like this:

```text
my-elk-stack/
├── docker-compose.yml
└── logstash/
    └── pipeline/
        └── logstash.conf
```

`docker-compose.yml`: Defines the three services, their configurations, networks, and volumes.
`logstash/pipeline/logstash.conf`: Contains the configuration for the Logstash pipeline.

## Installation and Configuration with Docker Compose

Follow these steps sequentially to build and secure your stack.

### Create the Logstash Pipeline Configuration (For processing Windows logs)

This file defines how Logstash receives data, what to do with it, and where to send it.
Create the file logstash/pipeline/logstash.conf and add the following configuration:

`./logstash/pipeline/logstash.conf`
```ini
input {
    beats {
        port => 5044
    }
    tcp {
        port => 5000
        codec => json_lines
    }
}

output {
    elasticsearch {
        hosts => ["http://elasticsearch:9200"]
        index => "logstash-%{+YYYY.MM.dd}"
        # Use environment variables for secure credential management
        user => "${ELASTICSEARCH_USERNAME}"
        password => "${ELASTICSEARCH_PASSWORD}"
    }
}
```

### Create the Initial docker-compose.yml

This file outlines the ELK services (Elasticsearch, Logstash, Kibana) without any sensitive passwords yet.
Create the docker-compose.yml file in your project's root directory:

`./docker-compose.yml`
```markdown
```yaml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.2
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
      - xpack.security.enabled=true
    volumes:
      - esdata:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"
      - "9300:9300"
    networks:
      - elknet

  logstash:
    image: docker.elastic.co/logstash/logstash:8.12.2
    container_name: logstash
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline:ro
    ports:
      - "5044:5044"
      - "5000:5000/tcp"
      - "5000:5000/udp"
    networks:
      - elknet
    depends_on:
      - elasticsearch

  kibana:
    image: docker.elastic.co/kibana/kibana:8.12.2
    container_name: kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    networks:
      - elknet
    depends_on:
      - elasticsearch

volumes:
  esdata:
    driver: local

networks:
  elknet:
    driver: bridge

```

### Generate Passwords for Built-in Users
This crucial security step creates unique, secure passwords for all internal ELK users.
Start only the Elasticsearch container:

  ```bash
  docker-compose up -d elasticsearch
  ``` 

Run the password generation script and **save the output**:

  ```bash
  docker exec -it elasticsearch /usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto
  ```
Stop the container:

  ```bash
  docker-compose down
  ```


### Generate a Kibana Encryption Key

This key encrypts sensitive data saved within Kibana, such as alerting configurations.
Generate a 32-character key using one of the commands below and save the output:
Bash

### For Linux/macOS/WSL
  ```bash
  openssl rand -hex 16
  ```

### Alternative command
  ```bash
  head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32
  ```

### Update docker-compose.yml with Credentials and Keys
Here, you embed the generated passwords and keys into your service definitions to secure the stack.

Edit your docker-compose.yml file and add the environment variables shown below. Replace the placeholder values (e.g., your_elastic_password) with the actual credentials you saved.

`./docker-compose.yml` **(Final Version)**

```markdown
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.2
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
      - xpack.security.enabled=true
      # --- ADD PASSWORD FOR THE 'elastic' SUPERUSER ---
      - ELASTIC_PASSWORD=your_elastic_password 
    volumes:
      - esdata:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"
      - "9300:9300"
    networks:
      - elknet

  logstash:
    image: docker.elastic.co/logstash/logstash:8.12.2
    container_name: logstash
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline:ro
    ports:
      - "5044:5044"
      - "5000:5000/tcp"
      - "5000:5000/udp"
    # --- ADD CREDENTIALS FOR LOGSTASH TO CONNECT TO ELASTICSEARCH ---
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=logstash_system
      - ELASTICSEARCH_PASSWORD=your_logstash_system_password
    networks:
      - elknet
    depends_on:
      - elasticsearch

  kibana:
    image: docker.elastic.co/kibana/kibana:8.12.2
    container_name: kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      # --- ADD CREDENTIALS FOR KIBANA TO CONNECT TO ELASTICSEARCH ---
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=your_kibana_system_password
      # --- ADD THE KIBANA ENCRYPTION KEY ---
      - XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=your_generated_32_character_key
    ports:
      - "5601:5601"
    networks:
      - elknet
    depends_on:
      - elasticsearch

volumes:
  esdata:
    driver: local

networks:
  elknet:
    driver: bridge
```


### Launch the Full ELK Stack
This command reads your final docker-compose.yml file and starts all the configured containers.
  ```bash
  docker-compose up -d
  ```

### Access Kibana
This is the final step to log in and access the ELK Stack's powerful user interface. [URL](http://localhost:5601)

**Username**: elastic

**Password**: The your_elastic_password you saved in Step 4.3.

## Post-Setup: Basic Configuration in Kibana

### Creating a Data View

This tells Kibana which Elasticsearch index pattern to use for discovering and analyzing your data.

  1. Navigate to Stack Management > Kibana > Data Views.
  2. Click Create data view.
  3. For the Name, enter logstash-*.
  4. Select a Timestamp field (usually @timestamp).
  5. Click Create data view.

### Creating Visualizations and Dashboards

This is where you build charts, graphs, and unified dashboards to visualize your log data.

  1. Navigate to the Visualize Library and click Create visualization.
  2. Choose a visualization type (e.g., Pie, Bar Chart) and select your logstash-* data view.
  3. Configure and save the visualization.
  4. Navigate to the Dashboard section, create a new dashboard, and add your saved visualizations from the library.

