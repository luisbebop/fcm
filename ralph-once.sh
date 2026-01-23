#!/bin/bash

IS_SANDBOX=1 claude --dangerously-skip-permissions "@PRD.md @progress.txt \
1. Read the PRD and progress file. \
2. Find the next incomplete task and implement it. \
3. Run your tests and type checks. \
4. Check if it is working, running the app. \
5. Commit your changes. \
6. Update progress.txt with what you did. \
ONLY DO ONE TASK AT A TIME."
