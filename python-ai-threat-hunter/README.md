# AI Threat Hunter

An AI-powered tool for detecting and analyzing cybersecurity threats in network logs using modern AI techniques.

## Overview

AI Threat Hunter is designed to analyze network logs for potential security threats using AI pattern recognition. The tool can identify various attack vectors including lateral movement, data exfiltration, command and control communications, and reconnaissance activities.

## Features

- Advanced threat pattern recognition
- Risk scoring and confidence assessment
- Actionable mitigation recommendations
- Continuous learning from new threat patterns
- Detailed narrative summaries of detected threats

## Installation

This project supports modern Python dependency management with both [Poetry](https://python-poetry.org/) and [uv](https://github.com/astral-sh/uv).

### Prerequisites

- Python 3.11 or higher
- Git

### Option 1: Installation with Poetry (Recommended)

1. **Install Poetry** if you don't have it already:
   ```bash
   curl -sSL https://install.python-poetry.org | python3 -
   ```

2. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/ai-threat-hunter.git
   cd ai-threat-hunter
   ```

3. **Install dependencies with Poetry**:
   ```bash
   poetry install
   ```

4. **Activate the virtual environment**:
   ```bash
   poetry shell
   ```

### Option 2: Installation with uv

[uv](https://github.com/astral-sh/uv) is a fast, reliable Python package installer and resolver.

1. **Install uv** if you don't have it already:
   ```bash
   pip install uv
   ```

2. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/ai-threat-hunter.git
   cd ai-threat-hunter
   ```

3. **Create and activate a virtual environment with uv**:
   ```bash
   uv venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

4. **Install dependencies with uv**:
   ```bash
   uv pip install -e .
   ```
   
   Or with Poetry-generated requirements.txt:
   ```bash
   uv pip install -r requirements.txt
   ```

5. **Running the tool with uv**:
   ```bash
   # Running the script directly
   uv python ai_threat_hunter.py
   
   # Running as a module
   uv python -m ai_threat_hunter
   
   # View command-line options
   uv python ai_threat_hunter.py --help
   ```

## Usage

### Command Line

The simplest way to use AI Threat Hunter is directly from the command line:

```bash
# Run with default settings and interactive output
python ai_threat_hunter.py

# Output results as JSON
python ai_threat_hunter.py --json

# Run in quiet mode (minimal output)
python ai_threat_hunter.py --quiet

# Using uv instead of python
uv python -m ai_threat_hunter
```

### Python API

For more advanced usage, you can integrate the AI Threat Hunter into your Python code:

```python
import json
import asyncio
from ai_threat_hunter import AIThreatHunter

# Sample network logs (in a real scenario, these would come from your SIEM or logs)
sample_logs = [
    {
        "timestamp": "2023-06-01T12:34:56",
        "source_ip": "192.168.1.100",
        "dest_ip": "192.168.1.5",
        "dest_port": 445,
        "protocol": "TCP",
        "action": "allowed"
    },
    {
        "timestamp": "2023-06-01T12:35:20",
        "source_ip": "192.168.1.100",
        "dest_ip": "192.168.1.5",
        "dest_port": 3389,
        "protocol": "TCP",
        "action": "allowed"
    }
]

# Initialize the threat hunter
threat_hunter = AIThreatHunter()

# Run the analysis
async def analyze_logs():
    analysis_result = await threat_hunter.analyze_network_logs(sample_logs)
    print(json.dumps(analysis_result, indent=2))

# Execute the analysis
asyncio.run(analyze_logs())
```

## Development Setup

For development, you can install all dependencies including development tools:

### With Poetry:

```bash
# Install with development dependencies
poetry install --with dev

# Generate requirements.txt for uv users
poetry export -f requirements.txt --output requirements.txt
```

### With uv:

```bash
# Install from requirements.txt
uv pip install -r requirements.txt

# Or install the package in development mode 
uv pip install -e .

# Install with development dependencies
uv pip install -e ".[dev]"
```

## License

[Your license information here]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
