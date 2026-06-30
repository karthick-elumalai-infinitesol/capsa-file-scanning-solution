import sqlite3
import os
from typing import Optional, Dict
from src.config import get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


class NSRLClient:
    def __init__(self):
        self.settings = get_settings()
        self.db_path = self.settings.nsrl_database_path
        self.conn = None
        self._init_database()

    def _init_database(self):
        """Initialize or connect to NSRL database."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            self._create_tables()
            logger.info(f"NSRL database ready at {self.db_path}")
        except Exception as e:
            logger.error(f"Error initializing NSRL database: {str(e)}")

    def _create_tables(self):
        """Create necessary tables if they don't exist."""
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_hashes (
                id INTEGER PRIMARY KEY,
                md5 TEXT UNIQUE,
                sha1 TEXT UNIQUE,
                sha256 TEXT UNIQUE,
                file_name TEXT,
                product_name TEXT,
                added_date TEXT
            )
        ''')
        self.conn.commit()

    def lookup_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Look up a file hash in the NSRL database.
        Returns file info if found, None otherwise.
        """
        if not self.conn:
            return None

        try:
            cursor = self.conn.cursor()

            # Try MD5 first (most common)
            cursor.execute('SELECT * FROM file_hashes WHERE md5 = ?', (file_hash.lower(),))
            row = cursor.fetchone()

            if not row:
                # Try SHA1
                cursor.execute('SELECT * FROM file_hashes WHERE sha1 = ?', (file_hash.lower(),))
                row = cursor.fetchone()

            if not row:
                # Try SHA256
                cursor.execute('SELECT * FROM file_hashes WHERE sha256 = ?', (file_hash.lower(),))
                row = cursor.fetchone()

            if row:
                return dict(row)

            return None

        except Exception as e:
            logger.error(f"Error looking up hash in NSRL: {str(e)}")
            return None

    def add_hash(self, md5: str = None, sha1: str = None, sha256: str = None,
                 file_name: str = None, product_name: str = None) -> bool:
        """Add a file hash to the NSRL database."""
        if not self.conn:
            return False

        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO file_hashes (md5, sha1, sha256, file_name, product_name, added_date)
                VALUES (?, ?, ?, ?, ?, datetime('now'))
            ''', (md5, sha1, sha256, file_name, product_name))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error adding hash to NSRL: {str(e)}")
            return False

    def bulk_add_hashes(self, hashes: list) -> int:
        """Add multiple hashes to the database. Returns count added."""
        if not self.conn:
            return 0

        added = 0
        try:
            cursor = self.conn.cursor()
            for hash_data in hashes:
                try:
                    cursor.execute('''
                        INSERT OR REPLACE INTO file_hashes (md5, sha1, sha256, file_name, product_name, added_date)
                        VALUES (?, ?, ?, ?, ?, datetime('now'))
                    ''', (
                        hash_data.get('md5'),
                        hash_data.get('sha1'),
                        hash_data.get('sha256'),
                        hash_data.get('file_name'),
                        hash_data.get('product_name'),
                    ))
                    added += 1
                except Exception as e:
                    logger.debug(f"Skipping hash: {str(e)}")

            self.conn.commit()
            return added
        except Exception as e:
            logger.error(f"Error bulk adding hashes: {str(e)}")
            return added

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()

    def __del__(self):
        self.close()
