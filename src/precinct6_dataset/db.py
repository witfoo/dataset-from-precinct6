"""Cassandra database connection management."""

import ssl
from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider
from cassandra.query import SimpleStatement

from precinct6_dataset.config import (
    CASSANDRA_HOST, CASSANDRA_PORT, CASSANDRA_USER,
    CASSANDRA_PASSWORD, CASSANDRA_SSL, CASSANDRA_FETCH_SIZE,
)


class CassandraConnector:
    """Manages SSL-authenticated connection to Cassandra."""

    def __init__(self, keyspace: str = None):
        self.keyspace = keyspace
        self.cluster = None
        self.session = None

    def connect(self) -> "CassandraConnector":
        auth = PlainTextAuthProvider(
            username=CASSANDRA_USER,
            password=CASSANDRA_PASSWORD,
        )

        kwargs = {
            "contact_points": [CASSANDRA_HOST],
            "port": CASSANDRA_PORT,
            "auth_provider": auth,
        }

        if CASSANDRA_SSL:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            kwargs["ssl_context"] = ssl_context

        self.cluster = Cluster(**kwargs)
        self.session = self.cluster.connect(self.keyspace)
        self.session.default_fetch_size = CASSANDRA_FETCH_SIZE
        return self

    def execute(self, query: str, params=None, fetch_size: int = None):
        """Execute a CQL query and return results."""
        stmt = SimpleStatement(query)
        if fetch_size:
            stmt.fetch_size = fetch_size
        return self.session.execute(stmt, params)

    def close(self):
        if self.cluster:
            self.cluster.shutdown()
            self.cluster = None
            self.session = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
