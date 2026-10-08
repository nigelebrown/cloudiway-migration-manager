import pymssql


class SqlSourceClient:
    def __init__(self, host: str, port: int, database: str, username: str, password: str):
        self.host = host
        self.port = int(port or 1433)
        self.database = database
        self.username = username
        self.password = password

    def test_connection(self) -> dict:
        if not all([self.host, self.database, self.username, self.password]):
            raise RuntimeError("SQL source settings are incomplete")
        connection = pymssql.connect(
            server=self.host,
            port=self.port,
            user=self.username,
            password=self.password,
            database=self.database,
            login_timeout=10,
            timeout=15,
        )
        try:
            cursor = connection.cursor()
            cursor.execute("SELECT DB_NAME(), SUSER_SNAME()")
            row = cursor.fetchone()
            return {
                "ok": True,
                "database": row[0] if row else self.database,
                "login": row[1] if row and len(row) > 1 else self.username,
            }
        finally:
            connection.close()
