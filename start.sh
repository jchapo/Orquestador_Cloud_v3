#!/bin/bash
cd /opt/pucp-orchestrator
source venv/bin/activate
source .env
python api_gateway.py
