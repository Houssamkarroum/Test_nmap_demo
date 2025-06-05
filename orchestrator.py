# orchestrator.py
# This script acts as the central coordinator for the distributed scanning system.
# It's responsible for network decomposition, task generation, and task distribution to Redis.
#
# Key Features:
# - Robust Redis connection with retry and exponential backoff.
# - Network decomposition into smaller, manageable IP segments.
# - Task packaging with comprehensive metadata (task_id, phase, retries, timestamp).
# - Efficient task distribution to Redis using RPUSH.
# - Prometheus metrics exposition for monitoring its operations.

import redis          # Python client for Redis, used for task queuing.
import ipaddress      # Standard library for IP address manipulation (network decomposition).
import time           # For delays and timestamps.
import sys            # For system exit.
import json           # For JSON serialization of tasks.
import logging        # For structured logging throughout the script.
import os             # For accessing environment variables for configuration.
from prometheus_client import start_http_server, Gauge, Counter # Prometheus client library for metrics.

# --- Configuration ---
# Redis connection details, retrieved from environment variables set by Docker Compose.
# Defaults are provided for local testing outside of a Docker Compose environment.
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_DB = 0 # Default Redis database index.

# Prometheus metrics port, retrieved from environment variables.
# This is the port on which the orchestrator will expose its metrics for Prometheus to scrape.
PROMETHEUS_METRICS_PORT = int(os.getenv('PROMETHEUS_METRICS_PORT', 8000))

# Configure basic logging for better visibility of orchestrator operations.
# Logs will be printed to standard output, visible in 'docker-compose logs orchestrator'.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global Redis connection object, initialized once and reused.
redis_client = None

# --- Prometheus Metrics Definitions ---
# These are the custom metrics exposed by the orchestrator application.
# Gauges represent a value that can go up and down (e.g., queue size).
# Counters represent a monotonically increasing value (e.g., total tasks pushed).

# Counter: Total number of scan tasks successfully pushed to Redis.
tasks_pushed_total = Counter(
    'orchestrator_tasks_pushed_total',
    'Total number of scan tasks pushed to the Redis queue by the orchestrator.'
)

# Gauge: Current number of tasks pending in the Redis queue.
# This metric is updated by the orchestrator after pushing tasks and periodically (or when checked).
redis_queue_size = Gauge(
    'orchestrator_redis_queue_size',
    'Current number of tasks in the Redis scan_queue.'
)

def get_redis_client():
    """
    Establishes and returns a robust Redis client connection.
    Includes reconnection logic with retries and exponential backoff to handle
    transient network issues or Redis not being immediately available (e.g., on startup).
    """
    global redis_client
    # If client is already connected and responsive, return it.
    if redis_client is not None:
        try:
            # Ping Redis to ensure the connection is still alive.
            redis_client.ping()
            return redis_client
        except redis.exceptions.ConnectionError:
            logging.warning("Existing Redis connection lost. Attempting to reconnect...")
            redis_client = None # Force a new connection attempt.

    # Attempt to establish a new connection with retries.
    retries = 10 # Number of retry attempts.
    for attempt in range(retries):
        try:
            logging.info(f"Attempting to connect to Redis at {REDIS_HOST}:{REDIS_PORT}... (Attempt {attempt + 1}/{retries})")
            client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, socket_connect_timeout=5)
            client.ping() # Sends a PING command to verify the connection.
            logging.info("Successfully connected to Redis.")
            redis_client = client # Store the successful connection globally.
            return redis_client
        except redis.exceptions.ConnectionError as e:
            logging.warning(f"Redis connection failed: {e}. Retrying in {2**attempt} seconds...")
            time.sleep(2**attempt) # Exponential backoff to avoid hammering the service.
        except Exception as e:
            logging.error(f"An unexpected error occurred during Redis connection attempt: {e}. Retrying...")
            time.sleep(2**attempt) # Still use exponential backoff for other errors.

    logging.critical("Failed to connect to Redis after multiple retries. Orchestrator cannot proceed. Exiting.")
    sys.exit(1) # Critical failure: orchestrator cannot function without Redis.

def generate_ip_segments(network_range_str, segment_prefix_length):
    """
    Divides a larger IP network range into smaller, manageable segments.
    Each segment will become a distinct task for a worker. This function
    implements the "Décomposition du Réseau" phase by the orchestrator.

    Arguments:
        network_range_str (str): The overall target network range (e.g., '10.0.0.0/8').
        segment_prefix_length (int): The desired prefix length for the smaller segments
                                     (e.g., 29 for /29 blocks, which contain 8 IPs).

    Returns:
        list: A list of network strings (e.g., '10.0.0.0/29', '10.0.0.8/29').
              Returns an empty list if there's an error or invalid input.
    """
    segments = []
    try:
        network = ipaddress.ip_network(network_range_str, strict=False)
        # Validate that the segment_prefix_length is greater than the input network's prefix length.
        # This ensures we are breaking down a larger network into smaller subnets.
        if segment_prefix_length <= network.prefixlen:
            logging.error(f"Error: Segment prefix length ({segment_prefix_length}) must be strictly "
                          f"greater than the target network prefix length ({network.prefixlen}). "
                          f"Cannot decompose '{network_range_str}' into smaller segments with this prefix.")
            return []

        # Use the subnets() method to generate all subnets of the specified new_prefix.
        for subnet in network.subnets(new_prefix=segment_prefix_length):
            segments.append(str(subnet))
    except ValueError as e:
        logging.error(f"Error: Invalid network range '{network_range_str}' or segment prefix length {segment_prefix_length}. Details: {e}")
        return []
    except Exception as e:
        logging.error(f"An unexpected error occurred during IP segment generation: {e}", exc_info=True)
        return []
    return segments

if __name__ == "__main__":
    logging.info("Orchestrator starting...")

    # Start Prometheus HTTP server for metrics exposition.
    # Metrics will be available at http://<orchestrator_ip>:<PROMETHEUS_METRICS_PORT>/metrics
    try:
        start_http_server(PROMETHEUS_METRICS_PORT)
        logging.info(f"Prometheus metrics exposed on port {PROMETHEUS_METRICS_PORT}")
    except Exception as e:
        logging.critical(f"Failed to start Prometheus HTTP server on port {PROMETHEUS_METRICS_PORT}: {e}. Exiting.", exc_info=True)
        sys.exit(1)

    r_client = get_redis_client() # Obtain a robust Redis client connection.

    # --- Target Network Configuration ---
    # !! IMPORTANT !!
    # This is the network range your workers will simulate scanning.
    # For a real-world scenario, this should be the actual internal network you wish to scan.
    # Based on your 'ip addr show' output and discussion, '192.168.75.0/24' is your Wi-Fi network.
    # Using this range will make the simulation relevant to your local environment.
    target_network = '192.0.2.0/24' # Example: Your local Wi-Fi network segment.

    # Defines the size of each scanning task (IP segment) that workers will process.
    # A /29 segment contains 8 IP addresses (typically 6 usable hosts for scanning).
    # This choice balances task granularity with efficiency.
    segment_task_prefix_length = 29

    # Generate the list of IP segments. This is the "Décomposition du Réseau" part.
    segments_to_scan = generate_ip_segments(target_network, segment_task_prefix_length)
    if not segments_to_scan:
        logging.critical("No segments generated. Orchestrator cannot proceed without tasks. Exiting.")
        sys.exit(1)

    logging.info(f"Generated {len(segments_to_scan)} segments (each a /{segment_task_prefix_length} block) from the target network {target_network}.")

    # --- Redis Queue Management ---
    # Clear any previous tasks from the Redis queue to ensure a clean slate for the current scan.
    try:
        r_client.delete('scan_queue') # Deletes the Redis list named 'scan_queue'.
        logging.info("Cleared previous 'scan_queue' in Redis to start fresh.")
    except redis.exceptions.RedisError as e:
        logging.error(f"Error clearing Redis queue: {e}. This might mean old tasks persist. Attempting to proceed anyway.", exc_info=True)
    except Exception as e:
        logging.error(f"An unexpected error occurred while clearing Redis queue: {e}. Attempting to proceed anyway.", exc_info=True)

    # Push each generated segment as a structured task onto the Redis queue.
    # This is the "Empaquetage du Travail" (Work Packaging) and distribution to the "File Redis" phase.
    for i, segment in enumerate(segments_to_scan):
        # Data Format in Redis: JSON-serialized dictionary
        # Each task is a dictionary containing the IP segment and crucial metadata.
        # This allows for a flexible and extensible task definition.
        task_data = {
            "segment": segment,                 # The IP network segment to be scanned.
            "task_id": f"task_{i:05d}",         # A unique identifier for this specific task (e.g., task_00001).
            "phase": "discovery_and_portscan",  # Indicates the current scanning phase for the worker.
                                                # For this PoC, we combine discovery and port scan.
            "retries": 0,                       # Counter for how many times this task has been retried due to worker errors.
            "priority": "normal",               # Can be used for prioritization (e.g., "high", "low").
            "created_at": time.time()           # Unix timestamp when the task was created.
        }
        # Serialize the Python dictionary into a JSON string.
        # Redis stores strings, so JSON serialization is necessary for structured data.
        task_json = json.dumps(task_data)

        try:
            r_client.rpush('scan_queue', task_json) # Adds the JSON task string to the right end of the Redis list.
            tasks_pushed_total.inc() # Increment the Prometheus counter for each task pushed.
            # Use logging.debug instead of info if you want less verbose output during task pushing.
            # logging.debug(f"Pushed task (ID: {task_data['task_id']}) for segment: {segment} to scan queue.")
        except redis.exceptions.RedisError as e:
            logging.error(f"Error pushing task {task_json} to Redis: {e}. This task might be lost.", exc_info=True)
            # In a production system, you might implement a dedicated retry mechanism for pushing tasks
            # or a fallback to a persistent storage if Redis is down.

    logging.info(f"All {len(segments_to_scan)} tasks have been successfully pushed to Redis.")

    # Update the Redis queue size gauge after all tasks have been pushed.
    try:
        current_queue_size = r_client.llen('scan_queue')
        redis_queue_size.set(current_queue_size)
        logging.info(f"Redis scan_queue size updated to {current_queue_size}.")
    except redis.exceptions.RedisError as e:
        logging.error(f"Error getting Redis queue length for metrics: {e}", exc_info=True)


    logging.info("The orchestrator has completed its task generation and distribution role.")
    logging.info("\nTo observe the workers in action and monitor the system, view the Docker Compose logs:")
    logging.info("  docker-compose logs -f")
    logging.info("Access Prometheus at http://localhost:9090 and Grafana at http://localhost:3000 to see metrics and scan results.")

    # The orchestrator will now stay alive to continue exposing its metrics via the HTTP server.
    # In a real-world scenario, you might have it run periodically or listen for external triggers.
    # For this PoC, it just generates tasks once and then remains idle but exposes metrics.
    # If the orchestrator is meant to be a one-shot process, you might remove the start_http_server
    # and let it exit, or add a long sleep here if metrics are desired for a while.
    while True:
        # Update queue size periodically even if not pushing new tasks, for up-to-date metric.
        try:
            current_queue_size = r_client.llen('scan_queue')
            redis_queue_size.set(current_queue_size)
        except redis.exceptions.RedisError:
            logging.warning("Failed to update Redis queue size metric (connection issue?).")
            # Attempt to re-establish Redis connection if ping fails in the next loop.
            get_redis_client()
        time.sleep(30) # Update queue size metric every 30 seconds.