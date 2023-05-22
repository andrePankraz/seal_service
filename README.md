<!---
This file was created by ]init[ AG 2023.
-->

# Seal Service

This service enables the signing / sealing of PDF documents.
A classical PDF metadata signature (PAdES with Timestamp and LTV) is supported as well as a printable "Visual Seal" (BSI TR-03171, BSI TR-03137-1 und ICAO: Doc 9303, Part 13).
The Service also supports a verification page with JavaScript-side validation (not Server-side).

## Start as local service with Test-UI

- Clone https://.../seal_service

      $ docker compose up

  - Will take some time at first start (images & packages are downloaded, >10 GB)
  - Wait & check if up and running
- Go to URL: http://localhost:8200/
  - Will take some time at first start (models are downloaded, several GB)

## Start for Development

- Clone https://.../seal_service

      $ docker compose --env-file docker/.envs/dev.env up

  - Will take some time at first start (images & packages are downloaded, >10 GB)
  - Wait & check if up and running
- Install [VS Code](https://code.visualstudio.com/)
  - Install Extension
    - Dev Containers
    - Docker
    - Markdown All in One
- Attach VS Code to Docker Container
  - Attach to running containers... (Lower left edge in VS Code)
    - select ai_development-python-1
  - Explorer Open folder -> /opt/ai_development
  - Run / Start Debug
    - VS Code Extension Python will be installed the first time (Wait and another Start Debug)
    - Select Python Interpreter
- Go to URL: http://localhost:8200/
  - Will take some time at first start (models are downloaded, several GB)
