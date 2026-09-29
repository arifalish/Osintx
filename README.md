# Osintx

High-concurrency Open-Source Intelligence (OSINT) framework orchestrating SpiderFoot, theHarvester, OWASP Amass, BBOT, and native reconnaissance modules into a unified Telegram intelligence agent.

## Structure
- `bot/`: Telegram bot command loop and alert dispatcher
- `engines/`: Modules for SpiderFoot, theHarvester, Amass, BBOT, and native DNS
- `core/`: Multi-threaded job scheduling, data normalization, correlation, and reports
- `config/`: Centralized settings and credentials
