import json
import os

from llama_index.core import Settings
from llama_index.llms.ollama import Ollama


def get_settings():
    settings_path = "/app/config/settings.json"
    if os.path.exists(settings_path):
        try:
            with open(settings_path) as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "ollama_url": "http://host.docker.internal:11434",
        "ollama_model": "llama3"
    }

def get_llm():
    """
    Initializes and returns the LlamaIndex LLM instance based on current settings.
    Automatically detects if the endpoint is OpenAI-compatible (like LiteLLM proxy) or native Ollama.
    """
    config = get_settings()
    url = config.get("ollama_url", "http://host.docker.internal:11434")
    model = config.get("ollama_model", "llama3")

    import requests
    is_openai = False
    try:
        # Check if the endpoint responds to the OpenAI format
        if requests.get(f"{url}/v1/models", timeout=2).status_code == 200:
            is_openai = True
    except Exception:
        pass

    if is_openai:
        from llama_index.llms.openai import OpenAI
        llm = OpenAI(
            model=model,
            api_base=url,
            api_key="sk-proxy", # OpenAI client requires a key, even if proxy ignores it
            request_timeout=120.0,
            max_retries=2
        )
    else:
        from llama_index.llms.ollama import Ollama
        llm = Ollama(
            model=model,
            base_url=url,
            request_timeout=120.0
        )
    return llm

def configure_global_settings():
    """
    Configures the global LlamaIndex Settings to use the Ollama LLM.
    """
    Settings.llm = get_llm()
    # Can configure embedding model here as well if needed

def test_connection():
    """
    Test if the LLM connection is working.
    """
    try:
        llm = get_llm()
        resp = llm.complete("Say 'pong' if you receive this.")
        return True, str(resp)
    except Exception as e:
        return False, str(e)
