# Network Traffic Analysis & Threat Hunting

Production-grade SOC tool for capturing, analyzing, and visualizing network traffic.

## Features
- Real-time packet capture (Scapy)
- Protocol analysis (DNS, HTTP, TCP, etc.)
- TCP session reconstruction
- Interactive dashboard with charts
- REST API for programmatic access

## Installation
1. Clone the repository.
2. Create a virtual environment: `python -m venv venv`
3. Activate: `source venv/bin/activate` (Linux) or `venv\Scripts\activate` (Windows)
4. Install dependencies: `pip install -r requirements.txt`
5. Set environment variables in `.env` (copy from `.env.example`)
6. Ensure you have tshark installed (for PyShark) and Scapy dependencies.

## Execution
- Run `python app.py`
- Access dashboard at `http://localhost:5000`
- Start capture via UI or API (`POST /api/capture/start`)

## Testing
- Run `python -m unittest discover tests`

## API Documentation
- `GET /api/stats` – Get overall statistics
- `GET /api/packets?limit=N` – Get recent packets
- `POST /api/capture/start` – Start packet capture
- `POST /api/capture/stop` – Stop packet capture
- `GET /api/capture/status` – Get capture status

## Future Improvements
- Integration with threat intelligence feeds
- Alerting and anomaly detection
- Distributed capture
- WebSockets for real-time updates
- Advanced machine learning models