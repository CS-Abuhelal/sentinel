import json
import sys
import urllib.error
import urllib.request

TIMEOUT_SECONDS = 5


def send(alert_file: str, api_key: str, hook_url: str) -> int:
    try:
        with open(alert_file, "rb") as handle:
            body = handle.read()
    except OSError:
        return 1
    try:
        json.loads(body)
    except ValueError:
        return 1
    request = urllib.request.Request(
        hook_url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return 0 if response.status == 202 else 1
    except (urllib.error.URLError, TimeoutError):
        return 1


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print("usage: custom-sentinel <alert_file> <api_key> <hook_url>", file=sys.stderr)
        return 2
    return send(argv[1], argv[2], argv[3])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
