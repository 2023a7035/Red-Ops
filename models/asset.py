"""
Asset and Service Model
Handles database operations for hosts and discovered network services.
"""
from database.db import get_db_connection

class AssetModel:
    @staticmethod
    def get_all():
        """Retrieve all assets ordered by criticality."""
        conn = get_db_connection()
        assets = conn.execute("""
            SELECT a.*, 
                   COUNT(DISTINCT s.id) AS service_count,
                   COUNT(DISTINCT v.id) AS vuln_count,
                   SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_vulns,
                   SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) AS high_vulns
            FROM assets a
            LEFT JOIN services s ON a.id = s.asset_id
            LEFT JOIN vulnerabilities v ON s.id = v.service_id
            GROUP BY a.id
            ORDER BY 
                CASE a.criticality 
                    WHEN 'CRITICAL' THEN 1 
                    WHEN 'HIGH' THEN 2 
                    WHEN 'MEDIUM' THEN 3 
                    ELSE 4 
                END
        """).fetchall()
        conn.close()
        return assets

    @staticmethod
    def get_by_id(asset_id: int):
        """Retrieve a single asset by its ID with all associated services and vulnerabilities."""
        conn = get_db_connection()
        asset = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
        if not asset:
            conn.close()
            return None

        services = conn.execute("""
            SELECT s.*, 
                   COUNT(v.id) AS vuln_count,
                   GROUP_CONCAT(v.cve_id, ', ') AS cve_list
            FROM services s
            LEFT JOIN vulnerabilities v ON s.id = v.service_id
            WHERE s.asset_id = ?
            GROUP BY s.id
            ORDER BY s.port ASC
        """, (asset_id,)).fetchall()

        asset["services"] = services
        conn.close()
        return asset

    @staticmethod
    def get_by_ip(ip_address: str):
        conn = get_db_connection()
        asset = conn.execute("SELECT * FROM assets WHERE ip_address = ?", (ip_address,)).fetchone()
        conn.close()
        return asset

    @staticmethod
    def upsert_asset(ip_address: str, hostname: str = None, os_name: str = "Unknown", 
                     os_version: str = "Unknown", mac_address: str = None, 
                     criticality: str = "MEDIUM", role: str = "Host", notes: str = None):
        """Insert or update an asset record."""
        conn = get_db_connection()
        existing = conn.execute("SELECT id FROM assets WHERE ip_address = ?", (ip_address,)).fetchone()
        if existing:
            conn.execute("""
                UPDATE assets 
                SET hostname = COALESCE(?, hostname),
                    os_name = COALESCE(?, os_name),
                    os_version = COALESCE(?, os_version),
                    mac_address = COALESCE(?, mac_address),
                    notes = COALESCE(?, notes),
                    status = 'active',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (hostname, os_name, os_version, mac_address, notes, existing["id"]))
            conn.commit()
            asset_id = existing["id"]
        else:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO assets (ip_address, hostname, os_name, os_version, mac_address, criticality, role, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (ip_address, hostname, os_name, os_version, mac_address, criticality, role, notes))
            conn.commit()
            asset_id = cur.lastrowid

        conn.close()
        return asset_id

    @staticmethod
    def upsert_service(asset_id: int, port: int, protocol: str = "tcp", service_name: str = "unknown",
                       product: str = None, version: str = None, state: str = "open", banner: str = None):
        """Insert or update a service associated with an asset."""
        conn = get_db_connection()
        existing = conn.execute(
            "SELECT id FROM services WHERE asset_id = ? AND port = ? AND protocol = ?",
            (asset_id, port, protocol)
        ).fetchone()

        if existing:
            conn.execute("""
                UPDATE services 
                SET service_name = ?, product = ?, version = ?, state = ?, banner = ?
                WHERE id = ?
            """, (service_name, product, version, state, banner, existing["id"]))
            conn.commit()
            service_id = existing["id"]
        else:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO services (asset_id, port, protocol, service_name, product, version, state, banner)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (asset_id, port, protocol, service_name, product, version, state, banner))
            conn.commit()
            service_id = cur.lastrowid

        conn.close()
        return service_id
