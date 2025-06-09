# Yara scanner OpenRelik worker

## Overview

This worker scans input files or folders with Yara rules. It sources the rules from a given directory. It supports disk images that will be mounted.

## Installation

OpenRelik yara worker can be installed by using the pre-build Docker image.

**Note on Privileges:** This worker requires `privileged` mode capabilities and the `/dev/` volume mapped to perform necessary mounting operations (e.g., mounting disk images). Be aware of the security implications of granting these privileges.

### Using Pre-built Docker Image

Update the `docker-compose.yml` to include `openrelik-worker-yara`.

```yaml
openrelik-worker-yara:
  container_name: openrelik-worker-yara
  image: ghcr.io/openrelik/openrelik-worker-yara:${OPENRELIK_WORKER_YARA_VERSION}
  platform: linux/amd64
  privileged: true
  restart: always
  environment:
    - REDIS_URL=redis://openrelik-redis:6379
  volumes:
    - ./data:/usr/share/openrelik/data
    - /dev:/dev
  command: "celery --app=src.app worker --task-events --concurrency=4 --loglevel=INFO -Q openrelik-worker-yara"
```


## Building, pushing and running fraken-x Docker image
The fraken-x source and container is build seperatly to keep the openrelik-worker-yara build independent and fast. The image is available at `ghcr.io/openrelik/fraken-x`

Build
```
$ docker build -t ghcr.io/openrelik/fraken-x -f Dockerfile.fraken .
```

Push
```
$ docker push ghcr.io/openrelik/fraken-x
```

Run
```
$ docker run -ti ghcr.io/openrelik/fraken-x fraken-x --help
Usage: fraken-x [OPTIONS] <--folder <FOLDER>|--testrules> <RULES>

Arguments:
  <RULES>  Specify a particular path to a file or folder containing the Yara rules to use

Options:
  -f, --folder <FOLDER>      Specify a particular folder to be scanned
      --testrules            Test the rules for syntax validity and then exit
      --magic <MAGIC>        A path under the rules path that contains File Magics [default: misc/file-type-signatures.txt]
      --minscore <MINSCORE>  Only rules with scores greater than this will be output [default: 40]
      --maxsize <MAXSIZE>    Only files less than this size will be scanned [default: 1073741824]
  -h, --help                 Print help

```
