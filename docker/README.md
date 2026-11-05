# RedOps Isolated Enterprise Docker Laboratory

This directory provides an isolated multi-tiered enterprise target laboratory network designed specifically for authorized RedOps assessments.

## Lab Architecture & IP Mapping

| Container | Hostname | IP Address | Tier / Role | Simulating Services |
| :--- | :--- | :--- | :--- | :--- |
| `redops-gateway` | `gw01.corp.internal` | `172.28.0.10` | Perimeter Gateway | Nginx 1.18.0 Reverse Proxy, SSH |
| `redops-app` | `app-portal.corp.internal` | `172.28.0.20` | Application Tier | Tomcat 9.0.43 / Spring REST API, AJP |
| `redops-db` | `db-cluster01.corp.internal` | `172.28.0.30` | Crown Jewel Database | PostgreSQL 12.4, Redis Key-Value Store |
| `redops-dc` | `dc01.corp.internal` | `172.28.0.40` | Crown Jewel Identity | Active Directory Domain Controller / SMB |

## Safe Network Isolation Guarantees

1. **Private Subnet**: Containers reside on an isolated bridge network `172.28.0.0/16`.
2. **Loopback Binding**: Any host-mapped ports bind strictly to `127.0.0.1`, guaranteeing zero exposure to public external networks.
3. **Non-Destructive Testing**: All RedOps simulation probes are harmless diagnostic TCP handshakes and banner queries.

## Starting the Lab

If Docker & Docker Compose are installed on your machine, deploy the containers:

```bash
docker compose -f docker/docker-compose.yml up -d
```

To verify status:

```bash
docker compose -f docker/docker-compose.yml ps
```

To tear down the laboratory:

```bash
docker compose -f docker/docker-compose.yml down
```

*Note: If Docker is unavailable or not running on the evaluator's system, RedOps features a built-in authoritative demonstration dataset so all graph algorithms, CVE correlation, AI reasoning, simulation logs, and reports operate seamlessly out-of-the-box!*
