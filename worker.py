import os
import time
import redis
import sys
import random
import psycopg2
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
from psycopg2 import OperationalError, Error
from redis.exceptions import ConnectionError as RedisConnectionError, RedisError
from prometheus_client import start_http_server, Gauge, Counter

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [Worker %(process)d] - %(message)s')

# --- Configuration from Environment Variables ---
REDIS_HOST = os.getenv('REDIS_HOST', 'redis') # Default to 'redis' service name
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_DB = 0

POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'postgres') # Default to 'postgres' service name
POSTGRES_DB = os.getenv('POSTGRES_DB', 'nmap_results')
POSTGRES_USER = os.getenv('POSTGRES_USER', 'nmap_user')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'nmap_password')

# Number of threads each worker will use for concurrent scanning simulations.
WORKER_THREADS = int(os.getenv('WORKER_THREADS', 10))

# --- DYNAMIC WORKER_ID AND PROMETHEUS_METRICS_PORT ---
# Use the Docker HOSTNAME (which is the container ID or service_name-replica_number)
# to derive a unique WORKER_ID for each scaled worker instance.
WORKER_ID = os.getenv('WORKER_ID', os.getenv('HOSTNAME', 'unknown_worker'))

# All worker containers will expose metrics on this internal port.
PROMETHEUS_METRICS_PORT = int(os.getenv('PROMETHEUS_METRICS_PORT', 8001))

# Global connection objects for Redis and PostgreSQL.
redis_client = None
postgres_conn = None

# --- Prometheus Metrics Definitions ---
segments_processed_total = Counter(
    'worker_segments_processed_total',
    'Total number of IP segments successfully processed by this worker.',
    ['worker_id']
)

hosts_active_total = Counter(
    'worker_hosts_active_total',
    'Total number of active hosts discovered by this worker.',
    ['worker_id']
)

ports_scanned_total = Counter(
    'worker_ports_scanned_total',
    'Total number of open ports/services found by this worker.',
    ['worker_id']
)

worker_errors_total = Counter(
    'worker_errors_total',
    'Total number of errors encountered by this worker.',
    ['worker_id']
)

redis_queue_size_worker_view = Gauge(
    'worker_redis_queue_size',
    'Current number of tasks in the Redis scan_queue (worker view).',
    ['worker_id']
)

def get_redis_client():
    """
    Establishes and returns a robust Redis client connection for the worker.
    Implements reconnection logic with exponential backoff.
    """
    global redis_client
    if redis_client is not None:
        try:
            redis_client.ping()
            return redis_client
        except RedisConnectionError:
            logging.warning("Existing Redis connection lost. Attempting to reconnect...")
            redis_client = None

    max_retries = 10
    for attempt in range(max_retries):
        try:
            logging.info(f"Attempting to connect to Redis at {REDIS_HOST}:{REDIS_PORT}... (Attempt {attempt + 1}/{max_retries})")
            client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, socket_connect_timeout=5)
            client.ping()
            logging.info("Successfully connected to Redis.")
            redis_client = client
            return redis_client
        except RedisConnectionError as e:
            logging.warning(f"Redis connection failed: {e}. Retrying in {2**attempt} seconds...")
            time.sleep(2**attempt)
        except Exception as e:
            logging.error(f"An unexpected error during Redis connection: {e}. Retrying...")
            time.sleep(2**attempt)

    logging.critical("Failed to connect to Redis after multiple retries. Worker cannot operate without Redis. Exiting.")
    sys.exit(1)

def get_postgres_connection():
    """
    Establishes and returns a PostgreSQL database connection.
    Includes reconnection logic with exponential backoff.
    """
    global postgres_conn
    if postgres_conn is not None:
        try:
            with postgres_conn.cursor() as cur:
                cur.execute("SELECT 1")
            return postgres_conn
        except OperationalError:
            logging.warning("Existing PostgreSQL connection lost. Attempting to reconnect...")
            postgres_conn = None
        except Exception:
            logging.warning("Existing PostgreSQL connection in unknown state. Attempting to reconnect...")
            postgres_conn = None

    max_retries = 10
    for attempt in range(max_retries):
        try:
            logging.info(f"Attempting to connect to PostgreSQL at {POSTGRES_HOST}... (Attempt {attempt + 1}/{max_retries})")
            conn = psycopg2.connect(
                host=POSTGRES_HOST,
                database=POSTGRES_DB,
                user=POSTGRES_USER,
                password=POSTGRES_PASSWORD,
                connect_timeout=5
            )
            logging.info("Successfully connected to PostgreSQL.")
            postgres_conn = conn
            return postgres_conn
        except OperationalError as e:
            logging.warning(f"PostgreSQL connection failed: {e}. Retrying in {2**attempt} seconds...")
            time.sleep(2**attempt)
        except Exception as e:
            logging.error(f"An unexpected error during PostgreSQL connection: {e}. Retrying...")
            time.sleep(2**attempt)

    logging.critical("Failed to connect to PostgreSQL after multiple retries. Worker cannot store results. Exiting.")
    sys.exit(1)

def init_db():
    """
    Initializes the PostgreSQL database table (`scan_results`) if it doesn't exist.
    Adds new columns for service version and OS detection.
    """
    conn = get_postgres_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id SERIAL PRIMARY KEY,
                ip_address VARCHAR(45) NOT NULL,  -- Increased for IPv6 support
                port INT,
                service VARCHAR(50),
                service_version VARCHAR(100),
                os_detection VARCHAR(100),
                scan_segment VARCHAR(50),         -- Increased for longer CIDR notations
                scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        # Ensure unique index still works, and update ON CONFLICT for new columns
        # (This index is sufficient, ON CONFLICT will handle updates)
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_ip_port
            ON scan_results (ip_address, port);
        """)
        conn.commit()
        cur.close()
        logging.info("Database table 'scan_results' ensured/created successfully.")
    except Error as e:
        logging.critical(f"Error initializing database table: {e}. Worker will exit.", exc_info=True)
        worker_errors_total.labels(worker_id=WORKER_ID).inc()
        sys.exit(1)
    except Exception as e:
        logging.critical(f"An unexpected error occurred during DB initialization: {e}. Worker will exit.", exc_info=True)
        worker_errors_total.labels(worker_id=WORKER_ID).inc()
        sys.exit(1)

import subprocess
import xml.etree.ElementTree as ET

def nmap_discover_hosts(ip_segment):
    """
    Uses nmap to discover live hosts in the segment with multiple detection methods.
    """
    try:
        # More aggressive host discovery:
        # -PE: ICMP Echo
        # -PP: ICMP Timestamp
        # -PS: TCP SYN to common ports
        # -n: No DNS resolution (faster)
        result = subprocess.run(
            ["sudo", "nmap", "-PE", "-PP", "-PS21,22,23,25,80,443,3389", 
             "-n", "--max-retries", "2", "-oX", "-", ip_segment],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180  # Increased timeout
        )
        if result.returncode != 0:
            logging.error(f"nmap host discovery failed: {result.stderr.decode()}")
            worker_errors_total.labels(worker_id=WORKER_ID).inc()
            return []

        xml_root = ET.fromstring(result.stdout)
        hosts = []
        for host in xml_root.findall("host"):
            status = host.find("status")
            addr = host.find("address")
            if (status is not None and 
                status.attrib.get("state") == "up" and 
                addr is not None and 
                addr.attrib.get("addrtype") == "ipv4"):
                hosts.append(addr.attrib["addr"])
        if hosts:
            hosts_count = len(hosts)
            hosts_active_total.labels(worker_id=WORKER_ID).inc(hosts_count)
            logging.info(f"Found {hosts_count} active hosts in segment {ip_segment}")
        else:
            logging.warning(f"No hosts found in segment {ip_segment} - verify network connectivity")
        return hosts
        
        

    except Exception as e:
        logging.error(f"Exception during nmap_discover_hosts: {e}", exc_info=True)
        worker_errors_total.labels(worker_id=WORKER_ID).inc()
        return []

def nmap_os_and_ports(ip):
    """Basic nmap port scan for common ports only."""
    try:
        scan_results = []
        result = subprocess.run(
            ["sudo", "nmap", "-sS", "--top-ports", "100", 
             "-n", "--max-retries", "1", "-T4", "-oX", "-", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=90
        )

        if result.returncode != 0:
            logging.warning(f"nmap scan failed for {ip}: {result.stderr.decode()}")
            worker_errors_total.labels(worker_id=WORKER_ID).inc()
            return []

        xml_root = ET.fromstring(result.stdout)
        host = xml_root.find("host")
        if host is None:
            logging.warning(f"No host information found for {ip}")
            return []

        # Get ports/services
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                state = port.find("state")
                if state is not None and state.attrib.get("state") == "open":
                    service = port.find("service")
                    port_info = {
                        "ip": ip,
                        "port": int(port.attrib["portid"]),
                        "service": service.attrib.get("name") if service is not None else "unknown",
                        "service_version": None,
                        "os_detection": None
                    }
                    scan_results.append(port_info)

        # If no open ports found, still create a record for the host
        if not scan_results:
            # Create a record with port 0 to indicate host is alive but no open ports
            host_record = {
                "ip": ip,
                "port": 0,  # Use port 0 to indicate "host alive, no open ports"
                "service": "host_alive",
                "service_version": None,
                "os_detection": None
            }
            scan_results.append(host_record)
            logging.info(f"Host {ip} is alive but no open ports found")
        else:
            ports_count = len(scan_results)
            ports_scanned_total.labels(worker_id=WORKER_ID).inc(ports_count)
            logging.info(f"Found {ports_count} open ports for {ip}")
        
        return scan_results

    except Exception as e:
        logging.error(f"Exception during nmap_os_and_ports for {ip}: {e}", exc_info=True)
        worker_errors_total.labels(worker_id=WORKER_ID).inc()
        return []

def process_segment(ip_segment):
    """Process a network segment."""
    logging.info(f"Starting scan for segment: {ip_segment}")
    
    # First discover hosts
    active_hosts_ips = nmap_discover_hosts(ip_segment)
    if not active_hosts_ips:
        logging.warning(f"No active hosts in segment {ip_segment}")
        return [], 0

    segments_processed_total.labels(worker_id=WORKER_ID).inc()
    # Then scan each host
    final_results = []
    successful_scans = 0
    failed_scans = 0

    with ThreadPoolExecutor(max_workers=min(WORKER_THREADS, len(active_hosts_ips))) as executor:
        future_to_ip = {executor.submit(nmap_os_and_ports, ip): ip for ip in active_hosts_ips}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                host_results = future.result()
                if host_results:
                    final_results.extend(host_results)
                    successful_scans += 1
                    # Check if it's just a "host alive" record
                    if len(host_results) == 1 and host_results[0].get('port') == 0:
                        logging.info(f"Host {ip} recorded as alive with no open ports")
                    else:
                        logging.info(f"Host {ip} scanned with {len(host_results)} open ports")
                else:
                    failed_scans += 1
                    logging.warning(f"Scan completely failed for {ip}")
            except Exception as exc:
                failed_scans += 1
                logging.error(f"Scan failed for {ip}: {exc}")
                worker_errors_total.labels(worker_id=WORKER_ID).inc()

    logging.info(f"Segment {ip_segment} complete: {successful_scans} successful, {failed_scans} failed")
    return final_results, len(active_hosts_ips)


def store_results_in_db(results, segment):
    """
    Stores the collected scan results (discovered services with versions and OS)
    into the PostgreSQL database.
    """
    # Unpack results tuple if needed
    if isinstance(results, tuple):
        results, _ = results  # Unpack (results, active_hosts_count)

    if not results:
        logging.info(f"No results to store for segment {segment}.")
        return

    conn = None
    max_retries = 3
    for attempt in range(max_retries):
        try:
            conn = get_postgres_connection()
            cur = conn.cursor()

            insert_values = []
            for res in results:
                try:
                    # Handle both dictionary and list formats
                    if isinstance(res, dict):
                        ip = res.get('ip')
                        port = res.get('port')
                        service = res.get('service') or None 
                        service_version = res.get('service_version') or None
                        os_detection = res.get('os_detection') or None
                    elif isinstance(res, (list, tuple)):
                        # Assuming the list/tuple follows the same order as the DB columns
                        ip = res[0] if len(res) > 0 else None
                        port = res[1] if len(res) > 1 else None
                        service = res[2] if len(res) > 2 else None
                        service_version = res[3] if len(res) > 3 else None
                        os_detection = res[4] if len(res) > 4 else None
                    else:
                        logging.warning(f"Skipping invalid result type {type(res)}: {res}")
                        continue

                    if ip and port is not None:
                        insert_values.append((ip, port, service, service_version, os_detection, segment))
                    else:
                        logging.warning(f"Skipping incomplete result: {res}")
                except Exception as e:
                    logging.warning(f"Error processing result {res}: {e}")
                    continue

            if not insert_values:
                logging.info(f"No valid results to insert for segment {segment}.")
                return

            # Execute the bulk insertion
            cur.executemany(
                """
                INSERT INTO scan_results (ip_address, port, service, service_version, os_detection, scan_segment)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (ip_address, port) DO UPDATE
                SET service = EXCLUDED.service,
                    service_version = EXCLUDED.service_version,
                    os_detection = EXCLUDED.os_detection,
                    scan_timestamp = CURRENT_TIMESTAMP;
                """,
                insert_values
            )

            conn.commit()
            cur.close()
            logging.info(f"Successfully stored {len(insert_values)} service entries for segment {segment}.")
            return

        except Exception as e:
            logging.error(f"Error storing results for {segment} (Attempt {attempt+1}/{max_retries}): {e}", exc_info=True)
            worker_errors_total.labels(worker_id=WORKER_ID).inc()
            if conn:
                conn.rollback()
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                logging.critical(f"Failed to store results for {segment} after multiple retries. Data might be lost.")
        except Error as e:
            logging.error(f"A general PostgreSQL error occurred storing results for {segment} (Attempt {attempt+1}/{max_retries}): {e}", exc_info=True)
            worker_errors_total.labels(worker_id=WORKER_ID).inc()
            if conn:
                conn.rollback()
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                logging.critical(f"Failed to store results for {segment} after multiple retries due to a general DB error. Data might be lost.")
        except Exception as e:
            logging.error(f"An unexpected error occurred while storing results for {segment} (Attempt {attempt+1}/{max_retries}): {e}", exc_info=True)
            worker_errors_total.labels(worker_id=WORKER_ID).inc()
            if conn:
                conn.rollback()
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                logging.critical(f"Failed to store results for {segment} after multiple retries due to unexpected error. Data might be lost.")

if __name__ == "__main__":
    worker_pid = os.getpid()
    logging.info(f"Worker process starting with {WORKER_THREADS} threads. WORKER_ID: {WORKER_ID}, Metrics Port: {PROMETHEUS_METRICS_PORT}")

    try:
        start_http_server(PROMETHEUS_METRICS_PORT)
        logging.info(f"Prometheus metrics exposed on port {PROMETHEUS_METRICS_PORT}")
    except Exception as e:
        logging.critical(f"Failed to start Prometheus HTTP server on port {PROMETHEUS_METRICS_PORT}: {e}. Exiting.", exc_info=True)
        sys.exit(1)

    init_db()
    r_client = get_redis_client()

    # The main worker loop
    while True:
        try:
            # BLPOP blocks until a task is available or timeout occurs
            # 'scan_queue' is the name of your Redis list
            task_raw = r_client.blpop('scan_queue', timeout=15)

            # Update queue size metric regardless of whether a task was found
            try:
                current_queue_size = r_client.llen('scan_queue')
                redis_queue_size_worker_view.labels(worker_id=WORKER_ID).set(current_queue_size)
            except RedisError:
                logging.warning("Failed to update Redis queue size metric (connection issue?).")

            if task_raw:
                # task_raw is a tuple: (queue_name, task_data_bytes)
                task_json_str = task_raw[1].decode('utf-8')
                
                try:
                    # Parse the JSON string into a Python dictionary
                    task_data = json.loads(task_json_str)
                    
                    # Extract data directly from the dictionary (THIS IS THE KEY CHANGE)
                    segment = task_data.get("segment")
                    task_id = task_data.get("task_id", "N/A")
                    phase = task_data.get("phase", "unknown")
                    retries = task_data.get("retries", 0) # Use .get() with a default for robustness


                    if not segment:
                        logging.warning(f"Received task (ID: {task_id}) from Redis with no 'segment' key. Skipping malformed task: {task_json_str}")
                        worker_errors_total.labels(worker_id=WORKER_ID).inc()
                        continue

                    logging.info(f"Picked up task (ID: {task_id}) for segment: {segment} (Phase: {phase}, Retries: {retries}).")

                    if phase == "discovery_and_portscan":
                        try:
                            scan_results, active_hosts_count = process_segment(segment)
                            
                            if active_hosts_count > 0:
                                if scan_results:
                                    store_results_in_db(scan_results, segment)
                                    logging.info(f"Stored {len(scan_results)} results for {active_hosts_count} hosts in {segment}")
                                else:
                                    logging.info(f"Found {active_hosts_count} hosts but no open ports in {segment}")
                            else:
                                logging.info(f"No active hosts found in segment {segment}")
                            
                            segments_processed_total.labels(worker_id=WORKER_ID).inc()
                            
                        except Exception as e:
                            logging.error(f"Error processing segment {segment}: {e}", exc_info=True)
                            worker_errors_total.labels(worker_id=WORKER_ID).inc()
                    else:
                        logging.warning(f"Unknown or unhandled phase '{phase}' for task ID {task_id}. Skipping processing.")
                        worker_errors_total.labels(worker_id=WORKER_ID).inc()

                    logging.info(f"Finished processing task (ID: {task_id}) for segment: {segment}.")

                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding JSON task from Redis: {e}. Raw task data: {task_json_str}", exc_info=True)
                    worker_errors_total.labels(worker_id=WORKER_ID).inc()
                except Exception as e:
                    # Catch any other unexpected errors during task processing
                    logging.error(f"An unexpected error occurred while processing task (ID: {task_id}) for segment {segment}: {e}", exc_info=True)
                    worker_errors_total.labels(worker_id=WORKER_ID).inc()

            else:
                logging.debug("No tasks in queue (timeout). Waiting for new tasks...")

        except RedisConnectionError as e:
            logging.error(f"Lost connection to Redis in main loop: {e}. Attempting to reconnect...")
            worker_errors_total.labels(worker_id=WORKER_ID).inc()
            redis_client = None # Reset client to force reconnection
            time.sleep(5)
        except Exception as e:
            # Catch any critical unhandled errors in the main loop itself
            logging.critical(f"A critical unhandled error occurred in the main worker loop: {e}. Worker will pause and retry.", exc_info=True)
            worker_errors_total.labels(worker_id=WORKER_ID).inc()
            time.sleep(10)