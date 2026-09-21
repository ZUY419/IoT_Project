TOOL_DESCRIPTION = [
    {
        "type": "function",
        "function": {
            "name": "run_nvd_lookup",
            "description": "[Stage 2] Queries NVD using the specific service, version, protocol, and port to map CVEs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "protocol": {
                        "type": "string",
                        "description": "The protocol of the service, either 'tcp' or 'udp'."
                    },
                    "port": {
                        "type": "string",
                        "description": "The port number of the service (e.g., '53', '80')."
                    },
                    "service_name": {
                        "type": "string",
                        "description": "The exact name of the software or service."
                    },
                    "version": {
                        "type": "string",
                        "description": "The version number of the service."
                    }
                },
                "required": ["protocol", "port", "service_name", "version"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_rag_poc",
            "description": "[Stage 2/3] Searches the local RAG knowledge base for specific device exploits, PoC scripts, or attack guidelines based on a keyword.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search keyword, usually a device brand, model, or CVE ID (e.g., 'D-Link DIR-816' or 'CVE-2017-14491')."
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_local_cve_details",
            "description": "[Stage 2/3] Directly retrieves CVE description and PoC from the local bucket storage using a CVE ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "The target CVE ID (e.g., 'CVE-2025-1000')."
                    }
                },
                "required": ["cve_id"]
            }
        }
    }
]