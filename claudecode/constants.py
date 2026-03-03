"""
Constants and configuration values for ClaudeCode.
"""

import os

# API Configuration
DEFAULT_CLAUDE_MODEL = os.environ.get('CLAUDE_MODEL') or 'claude-opus-4-1-20250805'
DEFAULT_OPENAI_MODEL = os.environ.get('OPENAI_MODEL') or 'ministral-3:3b'
DEFAULT_OPENAI_BASE_URL = os.environ.get('OPENAI_BASE_URL') or 'http://127.0.0.1:11434/v1'
DEFAULT_TIMEOUT_SECONDS = 180  # 3 minutes
DEFAULT_MAX_RETRIES = 3
RATE_LIMIT_BACKOFF_MAX = 30  # Maximum backoff time for rate limits

# Token Limits
PROMPT_TOKEN_LIMIT = 16384  # 16k tokens max for claude-opus-4
DEFAULT_OPENAI_MAX_TOKENS = 16384

# Exit Codes
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_CONFIGURATION_ERROR = 2

# Subprocess Configuration
SUBPROCESS_TIMEOUT = 1200  # 20 minutes for Claude Code execution

# LLM Provider Configuration
SUPPORTED_LLM_PROVIDERS = ['anthropic', 'openai']
DEFAULT_LLM_PROVIDER = 'openai' # os.environ.get('LLM_PROVIDER') or 'anthropic'
