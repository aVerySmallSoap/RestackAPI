# Restack API

> [!NOTE]
>
> This is a rewrite and restructure of the old *[Restack API](https://github.com/aVerySmallSoap/Capstone_Flask_API)*. Further commits and improvements to the project will be ported into this repository instead

> [!WARNING]
>
> This repository mostly offers simple functionality and the structure of the project

Restack API is the bridge that connects the web UI with scanner orchestration. The API allows users to scan URLs using three scanners— *Wapiti*, *OWASP Zap*, and *Arachni*.


## Building

To build the project, you first have to install some of its requirements such as:

* Python >3.13

This should allow you to start building and using the application for yourself.


## Configuration

The application requires little configuration for the user to start it properly. Most of the configuration should be set on a json file named ***ENV***.

The files should be located inside a config folder within the project.

```zsh
mkdir ./config
```

The json structure should look like the following:

```json
{
  "IP_ADDRESS": "127.0.0.1",
  "HOST": "localhost",
  "PORT": "8000",
  "DATABASE": "postgres+pycogs2://localhost:port@user:pass",
  "DB_NAME": "restack",
  "DB_USER": "user",
  "DB_PASS": "pass",
}
```

## Dependencies

### Python Packages

The project depends on some python libraries/packages such as:

* FastAPI
* Uvicorn
* SQLAlchemy
* SQLAlchemy-utils
* tz
* pycogs2
* Wapiti

```zsh
pip install fastapi uvicorn sqlalchemy sqlalchemy-utils tz pycogs2 wapiti3
```

### Scanner Integrations

The API depends on three highly popular and well tested web application vulnerability scanners—

* Wapiti
* OWASP Zap
* Arachni

### External Dependencies

The API also relies on these external tools to achieve its functionality:

* Docker
* Postgresql
