-- postgres_init.sql

-- Enable uuid-ossp for UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Table to track scan jobs (e.g., /24 segments)
CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    network_segment VARCHAR(20) NOT NULL UNIQUE, -- e.g., 192.168.1.0/24
    current_phase VARCHAR(50) NOT NULL, -- phase1, phase2, phase3, completed, failed
    status VARCHAR(50) NOT NULL, -- pending, in_progress, completed, failed
    attempts INT DEFAULT 0,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Table to store discovered hosts
CREATE TABLE IF NOT EXISTS nmap_hosts (
    host_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address INET UNIQUE NOT NULL,
    mac_address MACADDR,
    hostname VARCHAR(255),
    os_guess VARCHAR(255),
    status VARCHAR(50), -- e.g., up, down
    last_scanned TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Table to store open ports for discovered hosts
CREATE TABLE IF NOT EXISTS nmap_ports (
    port_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    host_id UUID NOT NULL REFERENCES nmap_hosts(host_id) ON DELETE CASCADE,
    port_number INT NOT NULL,
    protocol VARCHAR(10) NOT NULL, -- e.g., tcp, udp
    service VARCHAR(255),
    version VARCHAR(255),
    state VARCHAR(50), -- e.g., open, filtered
    product VARCHAR(255),
    extra_info TEXT,
    last_scanned TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_host_port_protocol UNIQUE (host_id, port_number, protocol)
);

-- Table to store Nmap script results
CREATE TABLE IF NOT EXISTS nmap_scripts (
    script_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    port_id UUID REFERENCES nmap_ports(port_id) ON DELETE CASCADE, -- Can be associated with a port
    host_id UUID REFERENCES nmap_hosts(host_id) ON DELETE CASCADE, -- Or directly with a host if port is not relevant
    script_name VARCHAR(255) NOT NULL,
    script_output TEXT,
    last_scanned TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for faster lookups
CREATE INDEX IF NOT EXISTS idx_scan_jobs_network ON scan_jobs (network_segment);
CREATE INDEX IF NOT EXISTS idx_nmap_hosts_ip ON nmap_hosts (ip_address);
CREATE INDEX IF NOT EXISTS idx_nmap_ports_host ON nmap_ports (host_id);
CREATE INDEX IF NOT EXISTS idx_nmap_ports_port ON nmap_ports (port_number);
CREATE INDEX IF NOT EXISTS idx_nmap_scripts_host ON nmap_scripts (host_id);
CREATE INDEX IF NOT EXISTS idx_nmap_scripts_port ON nmap_scripts (port_id);