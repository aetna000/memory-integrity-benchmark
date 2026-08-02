# System configurations

Published runs freeze their effective, non-secret adapter configuration under
`results/<run_id>/system-configurations/`. Credentials must never be committed.
Environment variables used only to locate services or choose documented models
are recorded by value; API keys are recorded as present/absent only.
