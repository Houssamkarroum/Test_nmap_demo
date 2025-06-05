# worker.py
# This script defines the behavior of a single distributed scanning worker.
# Each worker pulls tasks from Redis, simulates network scans, and stores results in PostgreSQL.
#
# Key Features:
# - Robust Redis and PostgreSQL connections with retry and exponential backoff.
# - Multithreaded simulated host discovery and port scanning.
# - Efficient storage of scan results into PostgreSQL with ON CONFLICT DO UPDATE handling.
# - Prometheus metrics exposition for granular monitoring of worker performance.

import os               # For accessing environment variables and process ID.
import time             # For delays and timestamps.
import redis            # Python client for Redis.
import random           # For simulating random scan outcomes.
import psycopg2         # PostgreSQL adapter for Python.
import ipaddress        # For IP address and network manipulation.
from concurrent.futures import ThreadPoolExecutor, as_completed # For multithreaded scanning.
import json             # For JSON deserialization of tasks.
import logging          # For structured logging.
from psycopg2 import OperationalError, Error # Specific PostgreSQL error types.
from redis.exceptions import ConnectionError as RedisConnectionError, RedisError # Specific Redis error types.
from prometheus_client import start_http_server, Gauge, Counter # Prometheus client library for metrics.

# Configure logging for the worker, outputting to standard output.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [Worker %(process)d] - %(message)s')

# --- Configuration from Environment Variables ---
# These variables are set by Docker Compose in docker-compose.yml.
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_DB = 0

POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'localhost')
POSTGRES_DB = os.getenv('POSTGRES_DB', 'nmap_results')
POSTGRES_USER = os.getenv('POSTGRES_USER', 'nmap_user')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'nmap_password')

# Number of threads each worker will use for concurrent scanning simulations.
# This directly impacts the worker's processing speed and demonstrates parallelism.
WORKER_THREADS = int(os.getenv('WORKER_THREADS', 10))

# Prometheus metrics port, retrieved from environment variables.
# Each worker instance will expose its metrics on this port.
PROMETHEUS_METRICS_PORT = int(os.getenv('PROMETHEUS_METRICS_PORT', 8001))

# Global connection objects for Redis and PostgreSQL.
# These are managed to ensure persistent and robust connections.
redis_client = None
postgres_conn = None

# --- Prometheus Metrics Definitions ---
# These are the custom metrics exposed by each worker instance.

# Counter: Total number of IP segments successfully processed by this worker.
segments_processed_total = Counter(
    'worker_segments_processed_total',
    'Total number of IP segments successfully processed by this worker.'
)

# Counter: Total number of active hosts discovered by this worker.
hosts_active_total = Counter(
    'worker_hosts_active_total',
    'Total number of active hosts discovered by this worker.'
)

# Counter: Total number of ports/services scanned and found by this worker.
ports_scanned_total = Counter(
    'worker_ports_scanned_total',
    'Total number of open ports/services found by this worker.'
)

# Counter: Total number of errors encountered by this worker during task processing or DB operations.
worker_errors_total = Counter(
    'worker_errors_total',
    'Total number of errors encountered by this worker.'
)

# Gauge: The current number of tasks available in the Redis scan_queue, as seen by this worker.
# This provides visibility into the shared queue from the worker's perspective.
redis_queue_size_worker_view = Gauge(
    'worker_redis_queue_size',
    'Current number of tasks in the Redis scan_queue (worker view).'
)

def get_redis_client():
    """
    Establishes and returns a robust Redis client connection for the worker.
    Implements reconnection logic with exponential backoff.
    """
    global redis_client
    # Check if an existing connection is active and responsive.
    if redis_client is not None:
        try:
            redis_client.ping()
            return redis_client
        except RedisConnectionError:
            logging.warning("Existing Redis connection lost. Attempting to reconnect...")
            redis_client = None # Force a new connection attempt.

    # Attempt to establish a new connection with retries.
    max_retries = 10
    for attempt in range(max_retries):
        try:
            logging.info(f"Attempting to connect to Redis at {REDIS_HOST}:{REDIS_PORT}... (Attempt {attempt + 1}/{max_retries})")
            client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, socket_connect_timeout=5)
            client.ping() # Test the connection.
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
    sys.exit(1) # Critical failure: worker cannot function without Redis.

def get_postgres_connection():
    """
    Establishes and returns a PostgreSQL database connection.
    Includes reconnection logic with exponential backoff.
    """
    global postgres_conn
    # Check if an existing connection is active and healthy.
    if postgres_conn is not None:
        try:
            # Check connection status, psycopg2.OperationalError indicates a bad connection.
            with postgres_conn.cursor() as cur:
                cur.execute("SELECT 1") # Simple query to test connection.
            return postgres_conn
        except OperationalError:
            logging.warning("Existing PostgreSQL connection lost. Attempting to reconnect...")
            postgres_conn = None # Force a new connection attempt.
        except Exception:
            logging.warning("Existing PostgreSQL connection in unknown state. Attempting to reconnect...")
            postgres_conn = None

    # Attempt to establish a new connection with retries.
    max_retries = 10
    for attempt in range(max_retries):
        try:
            logging.info(f"Attempting to connect to PostgreSQL at {POSTGRES_HOST}... (Attempt {attempt + 1}/{max_retries})")
            conn = psycopg2.connect(
                host=POSTGRES_HOST,
                database=POSTGRES_DB,
                user=POSTGRES_USER,
                password=POSTGRES_PASSWORD,
                connect_timeout=5 # Timeout for the connection attempt itself.
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
    sys.exit(1) # Critical failure: worker cannot function without a database connection.

def init_db():
    """
    Initializes the PostgreSQL database table (`scan_results`) if it doesn't exist.
    This ensures the table structure is ready when the worker attempts to insert data.
    """
    conn = get_postgres_connection()
    try:
        cur = conn.cursor()
        # Create the 'scan_results' table to store discovered hosts, ports, and services.
        # This table design supports the basic requirements for storing scan outputs.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id SERIAL PRIMARY KEY,              -- Unique identifier for each scan result entry.
                ip_address VARCHAR(15) NOT NULL,    -- The IPv4 address of the discovered host.
                port INT,                           -- The port number of the discovered service.
                service VARCHAR(50),                -- A descriptive name for the service (e.g., 'HTTP', 'SSH').
                scan_segment VARCHAR(20),           -- The original IP segment (e.g., '10.0.0.0/29') this result came from.
                scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP -- Timestamp of the discovery/last update.
            );
        """)
        # Create a unique index on 'ip_address' and 'port'.
        # This prevents duplicate entries for the same service on the same host.
        # 'ON CONFLICT DO UPDATE' handles updates gracefully if a duplicate is inserted,
        # updating the 'service' and 'scan_timestamp' fields, which is useful for re-scans.
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_ip_port
            ON scan_results (ip_address, port);
        """)
        conn.commit() # Commit the transaction to make changes permanent.
        cur.close()
        logging.info("Database table 'scan_results' ensured/created successfully.")
    except Error as e:
        logging.critical(f"Error initializing database table: {e}. Worker will exit.", exc_info=True)
        worker_errors_total.inc() # Increment error metric on DB init failure.
        sys.exit(1) # If table creation fails, the worker cannot store data, so it should exit.
    except Exception as e:
        logging.critical(f"An unexpected error occurred during DB initialization: {e}. Worker will exit.", exc_info=True)
        worker_errors_total.inc()
        sys.exit(1)

def simulate_ping(ip_address):
    """
    Simulates a network ping or host discovery process for a single IP address.
    In a real Nmap scenario, this would involve 'nmap -sn <ip>' or similar host discovery techniques.
    Returns the IP address if it's considered 'active', otherwise returns None.
    Simulates network latency and varying success rates.
    """
    time.sleep(random.uniform(0.1, 0.5)) # Simulate variable network latency and processing time.
    # Simulate an active host with a 25% probability for a more dynamic simulation.
    is_active = random.choice([True, False, False, False])
    if is_active:
        logging.debug(f"  Host {ip_address} is active (simulated).")
    return ip_address if is_active else None

def simulate_port_scan(ip_address):
    """
    Simulates a port and service scan for a single active host.
    In a real Nmap scenario, this would involve 'nmap -p- -sV <ip>' to detect open ports and identify services.
    Returns a list of dictionaries, where each dictionary represents a discovered service (IP, port, service name).
    """
    discovered_services = []
    # A mapping of common ports to their typical services for realistic simulation.
    common_ports = {
        22: "SSH", 80: "HTTP", 443: "HTTPS", 3389: "RDP", 21: "FTP", 23: "Telnet",
        25: "SMTP", 53: "DNS", 135: "RPC", 139: "NetBIOS", 445: "SMB", 1433: "MSSQL",
        1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL", 5985: "WinRM", 8080: "HTTP-Alt"
    }

    # Simulate finding between 0 and 3 open ports on a given active host.
    num_open_ports = random.randint(0, 3)
    if num_open_ports > 0:
        # Randomly select a subset of common ports to be "open" on this host.
        open_ports_info = random.sample(list(common_ports.items()), k=num_open_ports)
        for port, service_name in open_ports_info:
            time.sleep(random.uniform(0.05, 0.2)) # Simulate scan time per port, adding to realism.
            discovered_services.append({'ip': ip_address, 'port': port, 'service': service_name})
            logging.debug(f"    Found {ip_address}:{port} ({service_name})")
    else:
        logging.debug(f"    No common open ports found on {ip_address}.")

    return discovered_services

def process_segment(ip_segment):
    """
    Main function for a worker to process a given IP segment.
    This function orchestrates the multi-phase scanning simulation (host discovery and port scanning)
    and leverages multithreading for concurrent operations within the worker.
    """
    logging.info(f"Starting processing for segment: {ip_segment}")

    active_hosts = []
    all_ips_in_segment = []
    try:
        network = ipaddress.ip_network(ip_segment, strict=False)
        # Get all usable host IP addresses within the segment, excluding network and broadcast.
        all_ips_in_segment = [str(ip) for ip in network.hosts()]
    except ValueError as e:
        logging.error(f"Invalid IP segment received: {ip_segment}. Error: {e}")
        worker_errors_total.inc() # Increment error metric on invalid segment.
        return [] # Return empty if the segment string is malformed.
    except Exception as e:
        logging.error(f"An unexpected error occurred while parsing segment {ip_segment}: {e}", exc_info=True)
        worker_errors_total.inc()
        return []

    if not all_ips_in_segment:
        logging.info(f"No usable IPs in segment {ip_segment}. Skipping scan for this segment.")
        return []

    # 1. Host Discovery Phase (Simulated Nmap -sn / ping scan)
    # Using ThreadPoolExecutor to concurrently 'ping' all IPs within the assigned segment.
    logging.info(f"Starting host discovery for {len(all_ips_in_segment)} IPs in {ip_segment} using {WORKER_THREADS} threads.")
    with ThreadPoolExecutor(max_workers=WORKER_THREADS) as executor:
        # Submit simulate_ping tasks for each IP address in the segment.
        future_to_ip = {executor.submit(simulate_ping, ip): ip for ip in all_ips_in_segment}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result_ip = future.result()
                if result_ip:
                    active_hosts.append(result_ip)
            except Exception as exc:
                logging.error(f"Host discovery failed for {ip}: {exc}", exc_info=True)
                worker_errors_total.inc() # Increment error metric on ping failure.

    logging.info(f"Discovered {len(active_hosts)} active hosts in segment {ip_segment}.")
    hosts_active_total.inc(len(active_hosts)) # Increment Prometheus counter for active hosts.

    # 2. Port and Service Scanning Phase (Simulated Nmap -p -sV)
    # Using ThreadPoolExecutor again to concurrently scan ports on each discovered active host.
    all_discovered_services = []
    if active_hosts:
        logging.info(f"Starting port/service scan for {len(active_hosts)} active hosts in {ip_segment} using {WORKER_THREADS} threads.")
        with ThreadPoolExecutor(max_workers=WORKER_THREADS) as executor:
            # Submit simulate_port_scan tasks for each active host.
            future_to_host = {executor.submit(simulate_port_scan, host): host for host in active_hosts}
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    services = future.result()
                    all_discovered_services.extend(services)
                except Exception as exc:
                    logging.error(f"Port scan generated an exception for host {host}: {exc}", exc_info=True)
                    worker_errors_total.inc() # Increment error metric on port scan failure.
    else:
        logging.info(f"No active hosts discovered in {ip_segment} to perform port scans on.")

    ports_scanned_total.inc(len(all_discovered_services)) # Increment Prometheus counter for discovered services.
    return all_discovered_services

def store_results_in_db(results, segment):
    """
    Stores the collected scan results (discovered services) into the PostgreSQL database.
    Implements retry logic for database operations to enhance robustness.
    """
    if not results:
        logging.info(f"No results to store for segment {segment}.")
        return

    conn = None
    max_retries = 3 # Max attempts to store results.
    for attempt in range(max_retries):
        try:
            conn = get_postgres_connection() # Get a fresh or existing healthy connection.
            cur = conn.cursor()

            # Prepare data for bulk insertion. This is more efficient than individual INSERT statements.
            insert_values = []
            for res in results:
                # Ensure all required keys exist, providing defaults if necessary to prevent errors.
                ip = res.get('ip')
                port = res.get('port')
                service = res.get('service')
                if ip and port is not None: # Ensure IP and port are valid.
                    insert_values.append((ip, port, service, segment))
                else:
                    logging.warning(f"Skipping malformed result: {res} from segment {segment}")

            if not insert_values:
                logging.info(f"No valid results to insert after filtering for segment {segment}.")
                return

            # Execute the bulk insertion.
            # ON CONFLICT (ip_address, port) DO UPDATE ensures that if an entry for the same IP and port
            # already exists, it is updated (service name, timestamp) instead of causing a unique constraint error.
            cur.executemany(
                """
                INSERT INTO scan_results (ip_address, port, service, scan_segment)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (ip_address, port) DO UPDATE
                SET service = EXCLUDED.service, scan_timestamp = CURRENT_TIMESTAMP;
                """,
                insert_values
            )

            conn.commit() # Commit the transaction to save changes to the database.
            cur.close()
            logging.info(f"Successfully stored {len(insert_values)} service entries for segment {segment} in PostgreSQL.")
            return # Exit function on successful storage.
        except OperationalError as e:
            logging.error(f"PostgreSQL operational error storing results for {segment} (Attempt {attempt+1}/{max_retries}): {e}")
            worker_errors_total.inc() # Increment error metric on DB operational error.
            if conn:
                conn.rollback() # Rollback the transaction on error to prevent partial writes.
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt) # Exponential backoff before retrying.
                logging.info(f"Retrying PostgreSQL insertion for {segment}...")
            else:
                logging.critical(f"Failed to store results for {segment} after multiple retries due to operational error. Data might be lost.")
        except Error as e:
            logging.error(f"A general PostgreSQL error occurred storing results for {segment} (Attempt {attempt+1}/{max_retries}): {e}", exc_info=True)
            worker_errors_total.inc() # Increment error metric on general DB error.
            if conn:
                conn.rollback()
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                logging.critical(f"Failed to store results for {segment} after multiple retries due to a general DB error. Data might be lost.")
        except Exception as e:
            logging.error(f"An unexpected error occurred while storing results for {segment} (Attempt {attempt+1}/{max_retries}): {e}", exc_info=True)
            worker_errors_total.inc() # Increment error metric on unexpected error.
            if conn:
                conn.rollback()
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                logging.critical(f"Failed to store results for {segment} after multiple retries due to unexpected error. Data might be lost.")

if __name__ == "__main__":
    worker_pid = os.getpid() # Get the process ID of the worker for unique logging.
    logging.info(f"Worker process starting with {WORKER_THREADS} threads.")

    # Start Prometheus HTTP server for metrics exposition for this worker instance.
    try:
        start_http_server(PROMETHEUS_METRICS_PORT)
        logging.info(f"Prometheus metrics exposed on port {PROMETHEUS_METRICS_PORT}")
    except Exception as e:
        logging.critical(f"Failed to start Prometheus HTTP server on port {PROMETHEUS_METRICS_PORT}: {e}. Exiting.", exc_info=True)
        sys.exit(1)

    # Initialize database connection and ensure table schema is ready.
    init_db()
    # Initialize Redis connection.
    r_client = get_redis_client()

    # Main worker loop: continuously pull tasks from Redis and process them.
    while True:
        try:
            # Block and wait for a task from the Redis queue using BLPOP (blocking left pop).
            # The timeout ensures the worker doesn't hang indefinitely if the queue is empty,
            # allowing it to periodically check for shutdown signals or gracefully exit.
            # 'task_raw' will be (queue_name, task_data_bytes) or None if timeout occurs.
            task_raw = r_client.blpop('scan_queue', timeout=15) # Shorter timeout to update queue size metric more frequently.

            # Update the Redis queue size metric from the worker's perspective.
            try:
                current_queue_size = r_client.llen('scan_queue')
                redis_queue_size_worker_view.set(current_queue_size)
            except RedisError:
                logging.warning("Failed to update Redis queue size metric (connection issue?).")
                # Connection error might be handled by get_redis_client() in the next loop.

            if task_raw:
                task_json_str = task_raw[1].decode('utf-8') # Decode the byte string from Redis.
                try:
                    # Data Format: JSON-serialized dictionary.
                    # Deserialize the JSON string back into a Python dictionary.
                    task_data = json.loads(task_json_str)
                    segment = task_data.get("segment") # Extract the IP segment.
                    # Extract other metadata for logging or conditional processing.
                    task_id = task_data.get("task_id", "N/A")
                    phase = task_data.get("phase", "unknown")
                    retries = task_data.get("retries", 0)

                    if not segment:
                        logging.warning(f"Received task (ID: {task_id}) from Redis with no 'segment' key. Skipping malformed task: {task_json_str}")
                        worker_errors_total.inc() # Increment error metric for malformed tasks.
                        continue # Skip to the next iteration to get a new task.

                    logging.info(f"Picked up task (ID: {task_id}) for segment: {segment} (Phase: {phase}, Retries: {retries}).")

                    # --- Main Task Processing Logic ---
                    # The worker's behavior can be adapted based on the 'phase' metadata.
                    # For this PoC, 'discovery_and_portscan' is the primary phase.
                    if phase == "discovery_and_portscan":
                        # Perform the simulated host discovery and port scan for the given segment.
                        discovered_services = process_segment(segment)
                        # Store the collected results into the PostgreSQL database.
                        store_results_in_db(discovered_services, segment)
                        segments_processed_total.inc() # Increment Prometheus counter for processed segments.
                    else:
                        logging.warning(f"Unknown or unhandled phase '{phase}' for task ID {task_id}. Skipping processing.")
                        worker_errors_total.inc() # Increment error metric for unhandled phases.

                    logging.info(f"Finished processing task (ID: {task_id}) for segment: {segment}.")

                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding JSON task from Redis: {e}. Raw task data: {task_json_str}", exc_info=True)
                    worker_errors_total.inc() # Increment error metric for JSON decode errors.
                    # A malformed JSON task indicates a data issue; it's best to skip it.
                except Exception as e:
                    logging.error(f"An unexpected error occurred while processing task (ID: {task_id}) for segment {segment}: {e}", exc_info=True)
                    worker_errors_total.inc() # Increment error metric for general task processing errors.
                    # In a production system, you might implement a task re-queuing strategy here:
                    # Increment task_data["retries"] and r_client.rpush('scan_queue', json.dumps(task_data))
                    # Or move it to a "dead-letter queue" if retries exceed a certain limit to prevent infinite loops.

            else:
                # If blpop times out (no tasks in queue), log that and continue waiting.
                # The worker stays alive to expose metrics and wait for new tasks.
                logging.debug("No tasks in queue (timeout). Waiting for new tasks...")
                # No 'break' here, as workers should continuously run and wait for tasks.

        except RedisConnectionError as e:
            logging.error(f"Lost connection to Redis in main loop: {e}. Attempting to reconnect...")
            worker_errors_total.inc() # Increment error metric for Redis connection loss.
            redis_client = None # Force the `get_redis_client` function to re-establish the connection.
            time.sleep(5) # Pause before attempting to reconnect to avoid busy-looping.
        except Exception as e:
            logging.critical(f"A critical unhandled error occurred in the main worker loop: {e}. Worker will pause and retry.", exc_info=True)
            worker_errors_total.inc() # Increment error metric for critical unhandled errors.
            time.sleep(10) # Longer pause for critical unhandled errors to prevent rapid crash-restart cycles.