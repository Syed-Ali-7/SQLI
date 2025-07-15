SQLI_PATTERNS = [
    # Basic Tautologies and Logical Operators
    r"(?i)\bOR\b\s+\d+\s*=\s*\d+",
    r"(?i)\bAND\b\s+\d+\s*=\s*\d+",
    r"(?i)'\s*OR\s*'\w+'\s*=\s*'\w+'",
    r'(?i)"\s*OR\s*"\w+"\s*=\s*"\w+"',
    r"(?i)\bOR\b\s+1=1",
    r"(?i)\bAND\s+1=1",
    r"(?i)'\s*OR\s*'1'\s*=\s*'1'",
    r'(?i)"\s*OR\s*"1"\s*=\s*"1"',

    # UNION-based Attacks
    r"(?i)\bUNION\b.*\bSELECT\b",
    r"(?i)\bSELECT\b.*\bFROM\b",
    r"(?i)\bUNION\b.*\bALL\b.*\bSELECT\b",
    r"(?i)\bUNION\b.*\bDISTINCT\b.*\bSELECT\b",

    # Common SQL Commands
    r"(?i)\bINSERT\b\s+INTO\b",
    r"(?i)\bDELETE\s+FROM\b",
    r"(?i)\bUPDATE\s+\w+\s+SET\b",
    r"(?i)\bDROP\s+TABLE\b",
    r"(?i)\bTRUNCATE\s+TABLE\b",
    r"(?i)\bALTER\s+TABLE\b",
    r"(?i)\bCREATE\s+TABLE\b",
    r"(?i)\bEXEC\b",
    r"(?i)\bEXECUTE\b",
    r"(?i)\bSHUTDOWN\b",

    # Stacked Queries (terminating current query and starting a new one)
    r";\s*DROP\b",
    r";\s*INSERT\b",
    r";\s*UPDATE\b",
    r";\s*DELETE\b",
    r";\s*EXEC\b",
    r";\s*SHUTDOWN\b",

    # Comment-based Attacks
    r"--",
    r"#",
    r"/\*.*?\*/",
    r"\/\*.*\*\/", 
    r"\x23", 
    r"\x2d\x2d", 

    # Time-based/Blind SQLi
    r"(?i)\bSLEEP\s*\(",
    r"(?i)\bWAITFOR\s+DELAY\b",
    r"(?i)\bBENCHMARK\s*\(",
    r"(?i)pg_sleep\s*\(",
    r"(?i)dbms_lock.sleep\s*\(",

    # Data Type Manipulation and Encoding
    r"(?i)0x[0-9a-fA-F]+", 
    r"(?i)\bCHAR\s*\(",
    r"(?i)\bCAST\s*\(",
    r"(?i)\bCONVERT\s*\(",
    r"(?i)base64\(",
    r"\bASCII\(",
    r"\bBIN\(",
    r"\bHEX\(",

    # Information Schema and System Tables
    r"(?i)\bINFORMATION_SCHEMA\b",
    r"(?i)\bTABLE_SCHEMA\b",
    r"(?i)\bTABLE_NAME\b",
    r"(?i)\bCOLUMN_NAME\b",
    r"(?i)sysobjects",
    r"(?i)syscolumns",
    r"(?i)user_tables",
    r"(?i)user_columns",

    # Blind SQLi Techniques
    r"(?i)'\s*AND\s+\d+\s*=\s*\d+\s*--",
    r'(?i)"\s*AND\s+\d+\s*=\s*\d+\s*--',
    r"(?i)\bLIKE\b\s+'%",
    r"(?i)\bIF\s*\(",
    r"(?i)\bCASE\b.*\bWHEN\b.*\bTHEN\b",

    # URL Encoded Characters
    r"%27", 
    r"%22", 
    r"%3D", 
    r"%2D%2D",
    r"%3B", 
    r"%20", 
    r"%23", 
    r"%2f%2a",
    r"%2a%2f", 

    # Advanced and Obfuscated Patterns
    r"(?i)\bexec\b\s*\(",
    r"(?i)\bsp_executesql\b",
    r"(?i)\bxp_cmdshell\b",
    r"@@version",
    r"@@servername",
    r"\bload_file\(",
    r"\boutfile\b",
    r"\bdumpfile\b",
    r"\binto\s+outfile\b",
    r"\binto\s+dumpfile\b",

    # Error-based SQLi
    r"(?i)'\s*UNION\s*SELECT\s*NULL,\s*NULL,\s*NULL,\s*NULL,\s*NULL,\s*NULL,\s*NULL,\s*NULL",
    r"(?i)'\s*UNION\s*SELECT\s*1,\s*2,\s*3,\s*4,\s*5,\s*6,\s*7,\s*8",
    r"(?i)'\s*UNION\s*SELECT\s*@@version",
    r"(?i)'\s*UNION\s*SELECT\s*@@servername",
    r"(?i)'\s*UNION\s*SELECT\s*user\(\)",
    r"(?i)'\s*UNION\s*SELECT\s*database\(\)",
    r"(?i)'\s*UNION\s*SELECT\s*current_user\(\)",
    r"(?i)'\s*UNION\s*SELECT\s*current_database\(\)"

    # XPath Injection
    r"'\s*or\s*'\d'='\d",
    r"count\(//\*\)",
    r"string-length\(",
    r"substring\("
]