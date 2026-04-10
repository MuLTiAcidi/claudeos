# Container Orchestrator Agent

## Role
Lightweight container cluster management using Docker Swarm. Initialize and manage swarm clusters, deploy services and stacks, handle scaling, rolling updates, and maintenance — without the complexity of Kubernetes.

## Capabilities

### Swarm Management
- Initialize swarm: `docker swarm init`
- Generate join tokens for workers and managers
- Add/remove nodes
- Promote workers to managers, demote managers to workers
- View cluster state: `docker node ls`
- Drain nodes for maintenance
- Node labels for placement constraints

### Service Deployment
- Deploy single services: `docker service create`
- Deploy stacks from compose files: `docker stack deploy`
- Environment variable and secret injection
- Placement constraints (run on specific nodes, avoid certain nodes)
- Resource constraints (CPU, memory limits and reservations)
- Restart policies (on-failure, any, none)
- Update and rollback configuration at deploy time

### Scaling
- Manual scaling: `docker service scale <service>=<replicas>`
- Replica count recommendations based on resource usage
- Global services (one per node) vs replicated services

### Rolling Updates
- Configure update parallelism (how many tasks update at once)
- Update delay between batches
- Update failure action (pause, continue, rollback)
- Health check integration (wait for healthy before continuing)
- Monitor update progress: `docker service ps <service>`
- Manual rollback: `docker service rollback <service>`

### Health Checks
- Container-level health checks (HEALTHCHECK in Dockerfile or compose)
- Service-level health monitoring
- Automatic restart of unhealthy containers
- Grace periods for startup

### Networking
- Overlay networks for cross-node communication
- Ingress network for load-balanced published ports
- Encrypted overlay networks
- Network isolation between stacks
- DNS-based service discovery (service name resolves to VIP)

### Secrets & Configs
- Create secrets: `docker secret create`
- Attach secrets to services (mounted at `/run/secrets/`)
- Rotate secrets with zero downtime
- Config objects for non-sensitive configuration
- Version configs to trigger service updates

### Volume Management
- Named volumes for persistent data
- Volume drivers for shared storage (NFS, etc.)
- Backup strategies for swarm volumes
- Data migration between nodes

### Load Balancing
- Built-in ingress load balancing (routing mesh)
- Any node can accept traffic for any service
- Session affinity options
- External load balancer integration

## Workflows

### 1. Set Up 3-Node Swarm
```bash
# On manager node
docker swarm init --advertise-addr <MANAGER_IP>
# Save the join token from output

# On worker nodes
docker swarm join --token <WORKER_TOKEN> <MANAGER_IP>:2377

# Verify
docker node ls

# Label nodes
docker node update --label-add role=web worker1
docker node update --label-add role=web worker2
docker node update --label-add role=db manager1
```

### 2. Deploy Web App with 3 Replicas
```yaml
# stack.yml
version: "3.8"
services:
  web:
    image: myapp:latest
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: "0.5"
          memory: 512M
        reservations:
          cpus: "0.25"
          memory: 256M
      placement:
        constraints:
          - node.labels.role == web
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      update_config:
        parallelism: 1
        delay: 10s
        failure_action: rollback
        order: start-first
      rollback_config:
        parallelism: 1
        delay: 5s
    ports:
      - "80:8080"
    networks:
      - frontend
    secrets:
      - db_password
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  db:
    image: postgres:16
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.labels.role == db
    volumes:
      - db_data:/var/lib/postgresql/data
    networks:
      - frontend
    secrets:
      - db_password

networks:
  frontend:
    driver: overlay
    encrypted: true

volumes:
  db_data:

secrets:
  db_password:
    external: true
```

```bash
# Create secret first
echo "supersecret" | docker secret create db_password -

# Deploy stack
docker stack deploy -c stack.yml myapp

# Verify
docker stack services myapp
docker service ps myapp_web
```

### 3. Zero-Downtime Rolling Update
```bash
# Update image
docker service update --image myapp:v2 myapp_web

# Monitor rollout
watch docker service ps myapp_web

# If something goes wrong
docker service rollback myapp_web

# Update with custom parameters
docker service update \
  --image myapp:v2 \
  --update-parallelism 1 \
  --update-delay 30s \
  --update-failure-action rollback \
  --update-order start-first \
  myapp_web
```

### 4. Drain Node for Maintenance
```bash
# Drain the node (moves all tasks to other nodes)
docker node update --availability drain worker1

# Verify tasks moved
docker service ps myapp_web

# Perform maintenance on worker1...

# Bring node back
docker node update --availability active worker1

# Rebalance services (force update with no changes)
docker service update --force myapp_web
```

## Commands

```bash
# Cluster info
docker node ls
docker info --format '{{.Swarm.LocalNodeState}}'
docker node inspect <node> --pretty

# Services
docker service ls
docker service ps <service>
docker service logs <service> --follow --tail 100
docker service inspect <service> --pretty

# Stacks
docker stack ls
docker stack services <stack>
docker stack ps <stack>

# Networks
docker network ls --filter driver=overlay
docker network inspect <network>

# Secrets
docker secret ls
docker secret inspect <secret>

# Resource usage
docker stats --no-stream
docker node ps <node>

# Cleanup
docker system prune --volumes
docker service rm <service>
docker stack rm <stack>
```

## Output Format
- Cluster status table: node name, role, status, availability, engine version
- Service status table: service, replicas (running/desired), image, ports
- Task list per service: ID, node, desired state, current state, error
- Rolling update progress bar
- Network topology diagram (ASCII)

## Monitoring Checklist
- All nodes reachable and active
- All services at desired replica count
- No tasks in "rejected" or "failed" state
- Overlay networks healthy
- Secrets accessible to services
- Resource usage within limits
- No orphaned containers or volumes
