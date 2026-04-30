import os
import json
import logging
import config
import kuzu_db
from llama_index.core.tools import FunctionTool
from llm_connector import get_llm

logger = logging.getLogger(__name__)

DB_PATH = config.DB_PATH

def get_db_schema() -> str:
    """Return the static schema of the Kuzu graph database."""
    return '''
Nodes:
- Host(id STRING, hostname STRING, ip STRING, os STRING)
- Router(id STRING, hostname STRING, ip STRING, os STRING)
- Interface(id STRING, name STRING, mac_address STRING, ipv4 STRING)
  # VPN tunnel interfaces use names like: tun*, wg*, tap*, vpn*, ovpn*, ipsec*, l2tp*, pptp*
- Service(id STRING, name STRING, port INT64, state STRING)
  # For known VPN ports, name contains the protocol identifier:
  #   wireguard  -> port 51820 (udp)
  #   ikev2      -> ports 500 and 4500 (udp/tcp)
  #   openvpn    -> port 1194 (udp/tcp)
  #   pptp       -> port 1723 (tcp)
  # state is "open" or "open|filtered"

Relationships:
- HAS_INTERFACE(FROM Host TO Interface)
- HAS_INTERFACE(FROM Router TO Interface)
- HAS_PORT(FROM Host TO Service)
- HAS_PORT(FROM Router TO Service)
- CONNECTS_TO(FROM Host TO Host)
- CONNECTS_TO(FROM Host TO Router)
- CONNECTS_TO(FROM Router TO Host)
- CONNECTS_TO(FROM Router TO Router)
'''

def execute_kuzu_query(cypher_query: str) -> str:
    """Execute a READ-ONLY Cypher query against Kuzu and return the results as a JSON string."""
    try:
        # Validate before opening the database — reject any write operations early.
        upper_query = cypher_query.upper()
        if any(keyword in upper_query for keyword in ["CREATE", "DELETE", "MERGE", "SET", "DROP"]):
            return json.dumps({"error": "Only MATCH and RETURN queries are allowed."})

        # Use the shared Database singleton so we never fight the .lock file
        # with the background ingestion agent (kuzu_loader).
        conn = kuzu_db.get_connection()
        try:
            results = conn.execute(cypher_query)
            output = []
            while results.has_next():
                output.append(results.get_next())
            return json.dumps(output, default=str)
        finally:
            conn.close()
    except Exception as e:
        logger.error(f"Kuzu query failed: {e}")
        return json.dumps({"error": str(e)})

def load_few_shots() -> str:
    """Load default and custom few-shot examples for text-to-cypher."""
    # Default examples requested by user
    defaults = [
        {"nl": "How many routers are there?", "cypher": "MATCH (r:Router) RETURN count(r) AS count;"},
        {"nl": "List all devices running HTTP", "cypher": "MATCH (h)-[:HAS_PORT]->(s:Service) WHERE s.port = 80 RETURN h.hostname, h.ip;"},
        {"nl": "Find all Ollama nodes", "cypher": "MATCH (h)-[:HAS_PORT]->(s:Service) WHERE s.port = 11434 RETURN h.hostname, h.ip;"},
        {"nl": "List OS types per device", "cypher": "MATCH (h:Host) RETURN h.hostname, h.os UNION MATCH (r:Router) RETURN r.hostname, r.os;"},
        {"nl": "All VPN connections", "cypher": "MATCH (h)-[:HAS_INTERFACE]->(i:Interface) WHERE i.name CONTAINS 'tun' OR i.name CONTAINS 'wg' OR i.name CONTAINS 'tap' OR i.name CONTAINS 'vpn' OR i.name CONTAINS 'ipsec' OR i.name CONTAINS 'l2tp' OR i.name CONTAINS 'pptp' RETURN h.hostname, 'interface' AS signal, i.name AS detail UNION MATCH (h)-[:HAS_PORT]->(s:Service) WHERE s.port IN [51820, 500, 4500, 1194, 1723] RETURN h.hostname, 'port' AS signal, s.name AS detail;"}
    ]
    
    # Allow overriding via settings
    custom_path = "/app/config/kuzu_few_shots.json"
    if os.path.exists(custom_path):
        try:
            with open(custom_path, "r") as f:
                custom_examples = json.load(f)
                if isinstance(custom_examples, list):
                    defaults = custom_examples
        except Exception:
            logger.warning(f"Failed to load custom few shots from {custom_path}")
            
    examples_str = ""
    for ex in defaults:
        examples_str += f"Question: {ex['nl']}\\nCypher: {ex['cypher']}\\n\\n"
        
    return examples_str

def query_network(nl_query: str) -> str:
    """End-to-end function that converts NL to Cypher, executes it, and synthesizes a response."""
    llm = get_llm()
    if not llm:
        return "LLM is not configured or reachable. Please check the Config page."
        
    schema = get_db_schema()
    examples = load_few_shots()
    
    # 1. Text-to-Cypher
    cypher_prompt = f"""You are a Kùzu Graph Database expert. Your task is to translate a natural language question into a valid Kùzu Cypher query.
Only output the raw Cypher query string. Do not include markdown formatting like ```cypher or explanations.

Schema:
{schema}

Examples:
{examples}

Question: {nl_query}
Cypher:"""

    try:
        cypher_response = llm.complete(cypher_prompt)
        cypher_query = cypher_response.text.strip()
        # Clean markdown if the LLM ignored instructions
        if cypher_query.startswith("```"):
            cypher_query = cypher_query.replace("```cypher", "").replace("```", "").strip()
            
        logger.info(f"[KuzuTool] Generated Cypher: {cypher_query}")
        
    except Exception as e:
        return f"Failed to generate Cypher query: {e}"
        
    # 2. Execute Query
    db_result = execute_kuzu_query(cypher_query)
    logger.info(f"[KuzuTool] DB Result: {db_result}")
    
    if "error" in db_result.lower() and "only match" not in db_result.lower():
        # If execution failed, we return the error for debugging
        return f"Database error when running generated query:\\nQuery: {cypher_query}\\nResult: {db_result}"
        
    # 3. Synthesize Final Answer
    synthesis_prompt = f"""You are a network intelligence assistant. A user asked a question about the network topology.
We executed a graph database query to find the answer.

Question: {nl_query}
Executed Cypher Query: {cypher_query}
Database Result (JSON): {db_result}

Based on the database result, provide a clear, conversational answer to the user's question. If the database result is empty or empty brackets [], say that no matching data was found. Do not mention that you ran a cypher query, just answer the question naturally.
Answer:"""

    try:
        final_response = llm.complete(synthesis_prompt)
        return final_response.text.strip()
    except Exception as e:
        return f"Failed to synthesize final answer: {e}"

# ---------------------------------------------------------------------------
# LlamaIndex FunctionTool — exposes execute_kuzu_query as a first-class tool
# so it can be plugged into any LlamaIndex agent or query engine.
# ---------------------------------------------------------------------------

kuzu_query_tool = FunctionTool.from_defaults(
    fn=execute_kuzu_query,
    name="execute_network_cypher_query",
    description=(
        "Execute a READ-ONLY Cypher query against the Kuzu network topology graph database. "
        "Use this to retrieve structured information about hosts, routers, interfaces, services, "
        "and their connections. Only MATCH and RETURN queries are allowed. "
        "Returns results as a JSON string."
    ),
)

if __name__ == "__main__":
    # Simple test execution
    print(query_network("How many routers are on the network?"))
