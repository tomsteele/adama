#!/usr/bin/env python3
"""Generate worker inventory from Compose services and SDK declarations.

No tool names, subscriptions, or eligibility rules are maintained here.
Requires Docker Compose and Python 3; runs no scanner handlers.
"""

import argparse
import json
import subprocess
import sys


def compose(*args, capture=False):
    result = subprocess.run(
        ["docker", "compose", *args], check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout if capture else None


def register(build=True, replace=False):
    config = json.loads(compose("config", "--format", "json", capture=True))
    services = sorted(
        name for name, service in config["services"].items()
        if service.get("labels", {}).get("io.adama.worker") == "true"
    )
    if not services:
        raise ValueError("Compose has no services labeled io.adama.worker=true")
    if build:
        compose("build", "work", *services)
    compose("up", "-d", "--wait", "nats")
    # Mark inventory incomplete before touching definitions. An interrupted or
    # failed deployment must not retain a previously complete inventory.
    compose("run", "--rm", "--no-deps", "-T", "work", "inventory", "begin")
    names = set()
    for service in services:
        args = ["run", "--rm", "--no-deps", "-T", "-e", "ADAMA_REGISTER_ONLY=1"]
        if replace:
            args += ["-e", "ADAMA_REGISTER_REPLACE=1"]
        registration = json.loads(compose(*args, service, capture=True))
        definition = registration["definition"]
        if definition["version"] != 1 or not definition["name"]:
            raise ValueError(f"{service} returned an invalid worker definition")
        names.add(definition["name"])
    compose("run", "--rm", "--no-deps", "-T", "work", "inventory", "set", *sorted(names))
    print(f"Registered {len(names)} workers from {len(services)} Compose services.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-build", action="store_true", help="use already rebuilt, registration-capable worker images")
    parser.add_argument("--replace", action="store_true", help="replace changed definitions after stopping affected workers")
    args = parser.parse_args()
    try:
        register(build=not args.no_build, replace=args.replace)
    except (subprocess.CalledProcessError, ValueError, KeyError) as error:
        print(f"Worker registration failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
