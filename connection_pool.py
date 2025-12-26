"""
Fixed MySQL Connection Pool with proper connection management.
Prevents hanging and ensures connections are always returned to pool.
"""

import json
import mysql.connector
import threading
from queue import Queue, Empty

_pool_instance = None
_pool_lock = threading.Lock()


class DBConnectionPool:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, conn_config=None, pool_size=5):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DBConnectionPool, cls).__new__(cls)
                cls._instance._initialized = False
        return cls._instance

    def __init__(self, conn_config=None, pool_size=5):
        if self._initialized:
            return

        if conn_config is None:
            raise ValueError("DBConnectionPool requires conn_config on first creation.")

        self.conn_config = conn_config
        self.pool_size = pool_size
        self.pool = Queue(maxsize=pool_size)
        self._lock = threading.Lock()
        self._initialized = True

        self._create_connections(pool_size)

    def _create_connections(self, n):
        """Create n connections and add to pool."""
        for i in range(n):
            try:
                conn = mysql.connector.connect(**self.conn_config)
                self.pool.put(conn)
                print(f"Created connection {i+1}/{n}")
            except Exception as e:
                print(f"Failed to create connection {i+1}: {e}")
                raise

    def get_connection(self, timeout=30):
        """
        Get a connection from the pool.
        Blocks until one is available or timeout expires.
        """
        try:
            conn = self.pool.get(timeout=timeout)

            if not conn.is_connected():
                print("Connection dead, recreating...")
                conn = mysql.connector.connect(**self.conn_config)

            return conn
        except Empty:
            raise TimeoutError("No available connections in pool")

    def return_connection(self, conn):
        """Return a connection back to the pool."""
        try:
            if conn.is_connected():
                conn.rollback()
                self.pool.put(conn)
            else:
                print("Connection dead on return, creating new one...")
                new_conn = mysql.connector.connect(**self.conn_config)
                self.pool.put(new_conn)
        except Exception as e:
            print(f"Error returning connection: {e}")

    def close_all(self):
        """Close all connections in the pool."""
        closed = 0
        while not self.pool.empty():
            try:
                conn = self.pool.get_nowait()
                conn.close()
                closed += 1
            except Empty:
                break
            except Exception as e:
                print(f"Error closing connection: {e}")
        print(f"Closed {closed} connections")

    def get_pool_status(self):
        """Get current pool status."""
        return {
            "pool_size": self.pool_size,
            "available": self.pool.qsize(),
            "in_use": self.pool_size - self.pool.qsize(),
        }


# Context Manager for Safe Connection Usage
class PooledConnection:
    """Context manager for safe connection handling."""

    def __init__(self, pool):
        self.pool = pool
        self.conn = None

    def __enter__(self):
        self.conn = self.pool.get_connection()
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.pool.return_connection(self.conn)


def get_connection_pool(pool_size=1):
    """Returns the global DBConnectionPool instance."""
    global _pool_instance

    with _pool_lock:
        if _pool_instance is None:
            with open("db_config.json", "r") as f:
                db_config = json.load(f)

            # Configure connection parameters
            db_config["compress"] = True
            db_config["connection_timeout"] = 10
            db_config["read_timeout"] = 30
            db_config["write_timeout"] = 30
            db_config["consume_results"] = True
            db_config["raise_on_warnings"] = False
            db_config["use_pure"] = False
            db_config["autocommit"] = True

            _pool_instance = DBConnectionPool(db_config, pool_size=pool_size)

    return _pool_instance


# ----------------------------------------------------
# Test Helper
# ----------------------------------------------------
def test_connection(pool):
    """Test connection using context manager."""
    try:
        # Using context manager ensures connection is returned
        with PooledConnection(pool) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()
            print("MySQL Version:", version)

            cursor.execute("SHOW SESSION STATUS LIKE 'Compression'")
            compression_status = cursor.fetchone()
            print("Compression Status:", compression_status)

            cursor.close()
            print("Connection OK, Compression OK")

        # Check pool status
        status = pool.get_pool_status()
        print(f"Pool Status: {status}")

    except Exception as e:
        print("Test failed:", e)
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    print("Initializing global connection pool...")
    pool = get_connection_pool(pool_size=3)

    print("\nTesting connection...")
    test_connection(pool)

    print("\nClosing pool...")
    pool.close_all()
