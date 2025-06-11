import os
import redis
import ipcalc
import time
import psycopg2
from psycopg2 import extras
from datetime import datetime
import json
import logging
from prometheus_client import start_http_server, Gauge, Counter

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Prometheus Metrics ---
JOBS_ENQUEUED = Counter('orchestrator_jobs_enqueued_total', 'Total jobs enqueued by orchestrator', ['network_segment', 'phase'])
JOBS_COMPLETED = Counter('orchestrator_jobs_completed_total', 'Total jobs completed by orchestrator', ['network_segment', 'phase'])
CURRENT_QUEUED_JOBS = Gauge('orchestrator_current_queued_jobs', 'Current number of jobs in Redis queue')
CURRENT_PROCESSING_JOBS = Gauge('orchestrator_current_processing_jobs', 'Current number of jobs being processed by workers')
DB_CONNECTION_STATUS = Gauge('orchestrator_db_connection_status', 'Status of DB connection (1=up, 0=down)')
ORCHESTRATOR_ERRORS = Counter('orchestrator_errors_total', 'Total errors encountered by orchestrator')

# --- Configuration from Environment Variables ---
REDIS_HOST = os.getenv('REDIS_HOST', 'redis') # Default to 'redis' service name
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_DB = 0

POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'postgres') # Default to 'postgres' service name
POSTGRES_DB = os.getenv('POSTGRES_DB', 'nmap_results')
POSTGRES_USER = os.getenv('POSTGRES_USER', 'nmap_user')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'nmap_password')

PROMETHEUS_METRICS_PORT = int(os.getenv('PROMETHEUS_METRICS_PORT', 8000))

# --- Global Redis Client (with robust connection) ---
redis_client = None # Renamed to avoid clash with 'r' in original code
SCAN_QUEUE = "scan_queue"
COMPLETED_QUEUE = "completed_scans" # Not directly used in enqueuing but good to have
PROCESSING_JOBS_LIST = "processing_jobs" # Not directly used in enqueuing but good to have

def get_redis_client():
    """Establishes and returns a robust Redis client connection."""
    global redis_client
    if redis_client is not None:
        try:
            redis_client.ping()
            return redis_client
        except redis.exceptions.ConnectionError:
            logging.warning("Existing Redis connection lost. Attempting to reconnect...")
            redis_client = None

    max_retries = 10
    for attempt in range(max_retries):
        try:
            logging.info(f"Attempting to connect to Redis at {REDIS_HOST}:{REDIS_PORT}... (Attempt {attempt + 1}/{max_retries})")
            client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, socket_connect_timeout=5, decode_responses=True)
            client.ping()
            logging.info("Successfully connected to Redis.")
            redis_client = client
            return redis_client
        except redis.exceptions.ConnectionError as e:
            logging.warning(f"Redis connection failed: {e}. Retrying in {2**attempt} seconds...")
            time.sleep(2**attempt)
        except Exception as e:
            logging.error(f"An unexpected error during Redis connection: {e}. Retrying...")
            time.sleep(2**attempt)
    logging.critical("Failed to connect to Redis after multiple retries. Orchestrator cannot operate without Redis. Exiting.")
    sys.exit(1)


# --- Global PostgreSQL Connection ---
postgres_conn = None

def get_db_connection():
    """Establishes and returns a PostgreSQL database connection."""
    global postgres_conn
    if postgres_conn is not None:
        try:
            # Check if the connection is still alive
            with postgres_conn.cursor() as cur:
                cur.execute("SELECT 1")
            DB_CONNECTION_STATUS.set(1)
            return postgres_conn
        except psycopg2.OperationalError:
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
            conn.autocommit = True # For simplicity, commit immediately
            logging.info("Successfully connected to PostgreSQL.")
            postgres_conn = conn
            DB_CONNECTION_STATUS.set(1)
            return postgres_conn
        except psycopg2.OperationalError as e:
            logging.warning(f"PostgreSQL connection failed: {e}. Retrying in {2**attempt} seconds...")
            time.sleep(2**attempt)
        except Exception as e:
            logging.error(f"An unexpected error during PostgreSQL connection: {e}. Retrying...")
            time.sleep(2**attempt)
    logging.critical("Failed to connect to PostgreSQL after multiple retries. Orchestrator cannot function without DB. Exiting.")
    sys.exit(1)

def init_db_tables():
    """Initializes the PostgreSQL database tables if they don't exist."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Table for scan results (same as worker's)
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
            cur.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_ip_port
                ON scan_results (ip_address, port);
            """)

            # Table to track scan jobs managed by the orchestrator
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    job_id SERIAL PRIMARY KEY,
                    network_segment VARCHAR(20) UNIQUE NOT NULL,
                    current_phase VARCHAR(50) NOT NULL,
                    status VARCHAR(50) NOT NULL, -- e.g., 'pending', 'in_progress', 'completed', 'failed'
                    attempts INT DEFAULT 0,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP
                );
            """)
            conn.commit()
            logging.info("Database tables 'scan_results' and 'scan_jobs' ensured/created successfully.")
    except Exception as e:
        logging.critical(f"Error initializing database tables: {e}. Orchestrator will exit.", exc_info=True)
        ORCHESTRATOR_ERRORS.inc()
        sys.exit(1)

def update_job_status(cursor, network_segment, phase, status, attempts_increment=0, completed_at=None):
    """Updates the status of a scan job in the database."""
    query = """
    INSERT INTO scan_jobs (network_segment, current_phase, status, attempts, started_at, last_updated_at, completed_at)
    VALUES (%s, %s, %s, %s, NOW(), NOW(), %s)
    ON CONFLICT (network_segment) DO UPDATE SET
        current_phase = EXCLUDED.current_phase,
        status = EXCLUDED.status,
        attempts = scan_jobs.attempts + %s, -- Increment attempts by the given value
        last_updated_at = NOW(),
        completed_at = EXCLUDED.completed_at
    RETURNING job_id;
    """
    try:
        cursor.execute(query, (network_segment, phase, status, attempts_increment, completed_at, attempts_increment))
        job_id = cursor.fetchone()[0]
        logging.info(f"DB: Updated job {network_segment} ({phase}) to {status}. Job ID: {job_id}")
        return job_id
    except Exception as e:
        logging.error(f"DB Error updating job status for {network_segment} ({phase}): {e}", exc_info=True)
        ORCHESTRATOR_ERRORS.inc()
        return None

def get_job_details(cursor, network_segment):
    """Fetches details for a specific network segment job."""
    query = "SELECT job_id, network_segment, current_phase, status, attempts, started_at, last_updated_at, completed_at FROM scan_jobs WHERE network_segment = %s;"
    try:
        cursor.execute(query, (network_segment,))
        return cursor.fetchone()
    except Exception as e:
        logging.error(f"DB Error fetching job details for {network_segment}: {e}", exc_info=True)
        ORCHESTRATOR_ERRORS.inc()
        return None

def get_active_hosts_in_segment(cursor, network_segment):
    """Counts active hosts found in a given network segment from scan_results."""
    # This query counts IPs within the segment that have at least one port entry,
    # indicating they were found active and scanned.
    query = """
    SELECT COUNT(DISTINCT ip_address) FROM scan_results
    WHERE scan_segment = %s;
    """
    try:
        cursor.execute(query, (network_segment,))
        return cursor.fetchone()[0]
    except Exception as e:
        logging.error(f"DB Error counting active hosts for {network_segment}: {e}", exc_info=True)
        ORCHESTRATOR_ERRORS.inc()
        return 0

def divide_network_into_chunks(network_range, chunk_size="/29"):
    """
    Divides a given network range into smaller chunks.
    Corrected to iterate through all subnets.
    """
    chunks = []
    try:
        network = ipcalc.Network(network_range)
        for subnet in network:
            if str(subnet.mask) == chunk_size:
                chunks.append(str(subnet))
            elif str(subnet.mask) < chunk_size:
                # If the input network is larger than chunk_size, iterate through subnets
                for sub_subnet in ipcalc.Network(str(subnet) + chunk_size):
                    chunks.append(str(sub_subnet))
            else: # If chunk_size is smaller than input mask, just add the input (should ideally not happen with common inputs)
                chunks.append(str(subnet))

    except Exception as e:
        logging.error(f"Error dividing network {network_range}: {e}", exc_info=True)
        ORCHESTRATOR_ERRORS.inc()
        return []
    return sorted(list(set(chunks))) # Return sorted unique chunks

def enqueue_scan_job(network_segment, phase, attempt=1):
    """
    Enqueues a job to Redis with proper JSON formatting and updates its status in DB.
    """
    r_client = get_redis_client() # Get the robust Redis client
    conn = get_db_connection()    # Get the robust DB connection

    task_data = {
        "segment": network_segment,
        "task_id": f"{network_segment}-{phase}-{int(time.time())}-{attempt}", # Unique task ID
        "phase": phase,
        "retries": attempt - 1 # How many times this specific task has been retried
    }
    task_json_str = json.dumps(task_data)

    try:
        r_client.lpush(SCAN_QUEUE, task_json_str)
        JOBS_ENQUEUED.labels(network_segment=network_segment, phase=phase).inc()

        with conn.cursor() as cursor:
            # Update job status in DB: increment attempts only if it's not the first attempt for this phase
            update_job_status(cursor, network_segment, phase, 'in_progress', attempts_increment=1)

        logging.info(f"Enqueued task for segment: {network_segment}, Phase: {phase}, Task ID: {task_data['task_id']}")

    except (redis.exceptions.RedisError, psycopg2.Error) as e:
        logging.error(f"Failed to enqueue job or update DB for {network_segment} ({phase}): {e}", exc_info=True)
        ORCHESTRATOR_ERRORS.inc()
    except Exception as e:
        logging.error(f"An unexpected error occurred during enqueueing for {network_segment} ({phase}): {e}", exc_info=True)
        ORCHESTRATOR_ERRETS.inc()

def orchestrate_scan_phases(conn, initial_segments):
    """
    Main orchestration loop. Manages job lifecycle and enqueues tasks based on status.
    This simplified version focuses on the 'discovery_and_portscan' phase.
    """
    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
        for segment in initial_segments:
            job_details = get_job_details(cursor, segment)

            if job_details:
                # Job exists, check its status
                current_phase = job_details['current_phase']
                status = job_details['status']

                if status == 'completed':
                    logging.info(f"Segment {segment} already completed. Skipping.")
                    continue
                elif status == 'in_progress':
                    logging.info(f"Segment {segment} is already in progress ({current_phase}). Will monitor.")
                    # In a real system, you might check last_updated_at and re-enqueue if stuck
                    continue
                elif status == 'failed':
                    logging.warning(f"Segment {segment} previously failed ({current_phase}). Consider re-enqueuing or manual intervention.")
                    # For now, let's re-enqueue to retry, but with an incremented attempt count
                    enqueue_scan_job(segment, current_phase, job_details['attempts'] + 1)
                    continue
                elif status == 'pending':
                    # If it's pending, enqueue it.
                    logging.info(f"Segment {segment} is pending. Enqueuing for initial scan.")
                    enqueue_scan_job(segment, 'discovery_and_portscan', 1) # Start phase 1
                    continue
            else:
                # New job, insert into DB and enqueue for initial scan
                logging.info(f"New segment {segment}. Enqueuing for initial scan.")
                update_job_status(cursor, segment, 'pending', 'pending', attempts_increment=0) # Mark as pending first
                enqueue_scan_job(segment, 'discovery_and_portscan', 1) # Then enqueue

        # After initial enqueuing, monitor the queue and update metrics
        r_client = get_redis_client()
        current_queued_jobs = r_client.llen(SCAN_QUEUE)
        CURRENT_QUEUED_JOBS.set(current_queued_jobs)
        logging.info(f"Current Redis queue size: {current_queued_jobs}")

        # This part simulates processing jobs. In a real system, workers would
        # consume from SCAN_QUEUE, and potentially push to a 'results' or 'completed' queue
        # or directly update DB. Here, we just monitor.
        # For simplicity in this PoC, we assume jobs are processed once enqueued
        # and rely on the worker updating the DB for 'completed' status.
        # So, the orchestrator periodically queries DB to see status.

        # Example of how the orchestrator would "know" about completed jobs:
        # It would need a way to receive completion signals, or regularly poll DB.
        # Let's add a basic polling loop to check status.
        logging.info("Orchestrator entering monitoring loop. Press Ctrl+C to exit.")
        while True:
            # Poll DB for jobs in 'in_progress' state to check if they're actually completed
            # This is a simple check, a more robust system might use a separate 'results' queue
            # or rely on workers pushing job IDs to a 'completed' list.
            try:
                with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                    cur.execute("SELECT network_segment, current_phase FROM scan_jobs WHERE status = 'in_progress';")
                    in_progress_jobs = cur.fetchall()

                    for job in in_progress_jobs:
                        segment = job['network_segment']
                        # Check if this segment now has results in scan_results table
                        active_hosts_count = get_active_hosts_in_segment(cur, segment)
                        # A simple heuristic: if active hosts are found, consider the scan "done" for this phase
                        # In a real system, you'd have more robust completion criteria (e.g., specific messages from worker)
                        if active_hosts_count > 0:
                            logging.info(f"Orchestrator detected completion of scan for {segment}. Updating status to 'completed'.")
                            update_job_status(cur, segment, job['current_phase'], 'completed', completed_at=datetime.now())
                            JOBS_COMPLETED.labels(network_segment=segment, phase=job['current_phase']).inc()

            except Exception as e:
                logging.error(f"Error during orchestrator monitoring loop: {e}", exc_info=True)
                ORCHESTRATOR_ERRORS.inc()

            # Update queue metrics periodically
            try:
                r_client = get_redis_client() # Re-get in case of connection issues
                current_queued_jobs = r_client.llen(SCAN_QUEUE)
                CURRENT_QUEUED_JOBS.set(current_queued_jobs)
                # For processing jobs, a more sophisticated mechanism is needed (e.g., workers reporting 'started' status)
                # For now, we'll keep it simple and assume processing = not in queue and not completed
                CURRENT_PROCESSING_JOBS.set(len(in_progress_jobs)) # Approximation based on DB status

            except redis.exceptions.RedisError as e:
                logging.warning(f"Redis error while updating queue metrics: {e}")
                ORCHESTRATOR_ERRORS.inc()
            except Exception as e:
                logging.warning(f"An unexpected error occurred while updating metrics: {e}", exc_info=True)
                ORCHESTRATOR_ERRORS.inc()

            time.sleep(5) # Wait before next check

def enqueue_scan_job(network_segment, phase, attempt=1):
    """
    Enqueues a job to Redis with proper JSON formatting and updates its status in DB.
    """
    r_client = get_redis_client() # Get the robust Redis client
    conn = get_db_connection()    # Get the robust DB connection

    task_data = {
        "segment": network_segment,
        "task_id": f"{network_segment}-{phase}-{int(time.time())}-{attempt}", # Unique task ID
        "phase": phase,
        "retries": attempt - 1 # How many times this specific task has been retried
    }
    task_json_str = json.dumps(task_data)

    try:
        r_client.lpush(SCAN_QUEUE, task_json_str) # Correctly using SCAN_QUEUE
        JOBS_ENQUEUED.labels(network_segment=network_segment, phase=phase).inc()

        with conn.cursor() as cursor:
            # Update job status in DB: increment attempts only if it's not the first attempt for this phase
            update_job_status(cursor, network_segment, phase, 'in_progress', attempts_increment=1)

        logging.info(f"Enqueued task for segment: {network_segment}, Phase: {phase}, Task ID: {task_data['task_id']}")

    except (redis.exceptions.RedisError, psycopg2.Error) as e:
        logging.error(f"Failed to enqueue job or update DB for {network_segment} ({phase}): {e}", exc_info=True)
        ORCHESTRATOR_ERRORS.inc() # Corrected name
    except Exception as e:
        logging.error(f"An unexpected error occurred during enqueueing for {network_segment} ({phase}): {e}", exc_info=True)
        ORCHESTRATOR_ERRORS.inc() # Corrected name

if __name__ == "__main__":
    logging.info(f"Orchestrator starting. Metrics Port: {PROMETHEUS_METRICS_PORT}")
    try:
        start_http_server(PROMETHEUS_METRICS_PORT)
        logging.info(f"Prometheus metrics exposed on port {PROMETHEUS_METRICS_PORT}")
    except Exception as e:
        logging.critical(f"Failed to start Prometheus HTTP server on port {PROMETHEUS_METRICS_PORT}: {e}. Exiting.", exc_info=True)
        sys.exit(1)

    init_db_tables() # Initialize orchestrator's DB tables (scan_jobs)
    # The worker's init_db will handle scan_results table

    # Define the initial network segments to scan
    # For testing, you might just use one or two.
    # If using a /8 or /16, divide_network_into_chunks will split it into /24s.
    # Example: '192.168.1.0/24' will result in ['192.168.1.0/24']
    # Example: '10.0.0.0/16' with '/24' chunk_size would yield 256 /24 chunks.
    INITIAL_SCAN_RANGES = [os.getenv('INITIAL_SCAN_RANGE', '192.168.1.0/24')]
    CHUNKS = []
    for r_range in INITIAL_SCAN_RANGES:
        CHUNKS.extend(divide_network_into_chunks(r_range, chunk_size="/29"))

    if not CHUNKS:
        logging.critical("No valid IP segments to scan. Please check INITIAL_SCAN_RANGE. Exiting.")
        sys.exit(1)

    logging.info(f"Orchestrator will manage {len(CHUNKS)} IP segments: {CHUNKS}")

    orchestrator_db_conn = get_db_connection() # Get DB connection for orchestration
    if orchestrator_db_conn:
        orchestrate_scan_phases(orchestrator_db_conn, CHUNKS)
    else:
        logging.critical("Orchestrator failed to get a database connection. Cannot proceed.")
        sys.exit(1)