# Tool Dashboard Launcher
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
python "$scriptPath\dashboard.py"
