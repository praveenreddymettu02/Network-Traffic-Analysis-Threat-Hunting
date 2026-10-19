@echo off
title Live Wi-Fi Traffic Capture to Render
echo ========================================================
echo  Streaming Live Wi-Fi Traffic to Render Dashboard
echo  Target: https://network-traffic-analysis-threat-hunting.onrender.com
echo ========================================================
echo.
python agent/capture_agent.py --server https://network-traffic-analysis-threat-hunting.onrender.com --batch-size 25 --interval 1.0
pause
