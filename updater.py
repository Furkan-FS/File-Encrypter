import urllib.request
import urllib.error
import json
import logging

logger = logging.getLogger(__name__)

def check_for_update(current_version: str):
    """
    Checks the GitHub Releases API to see if a newer version is available.
    Returns a dict with 'version' and 'url' if an update is found, else None.
    """
    url = "https://api.github.com/repos/RPM147/File-Encrypter/releases/latest"
    
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status != 200:
                return None
            
            data = json.loads(response.read().decode('utf-8'))
            tag_name = data.get("tag_name", "")
            
            # Strip "v" if present
            if tag_name.startswith("v"):
                latest_version = tag_name[1:]
            else:
                latest_version = tag_name
                
            if not latest_version:
                return None
                
            # Semantic version comparison.
            # Strip any pre-release/build suffix (e.g. "1.2.0-beta", "1.2.0-rc1",
            # "1.2.0+build5") before parsing, otherwise the suffixed segment fails
            # isdigit() and gets dropped, which could misorder versions or report a
            # pre-release as a newer stable release.
            clean_current = current_version.split("-")[0].split("+")[0]
            clean_latest = latest_version.split("-")[0].split("+")[0]
            current_parts = [int(x) for x in clean_current.split(".") if x.isdigit()]
            latest_parts = [int(x) for x in clean_latest.split(".") if x.isdigit()]
            
            # Pad with zeros to handle missing patch numbers if any
            while len(current_parts) < 3: current_parts.append(0)
            while len(latest_parts) < 3: latest_parts.append(0)
            
            # Compare part by part
            is_newer = False
            for c, l in zip(current_parts, latest_parts):
                if l > c:
                    is_newer = True
                    break
                elif l < c:
                    break
            
            if is_newer:
                return {
                    "version": latest_version,
                    "url": data.get("html_url", "https://github.com/RPM147/File-Encrypter/releases/latest"),
                    "changelog": data.get("body", "")
                }
                
    except (urllib.error.URLError, urllib.error.HTTPError,
            json.JSONDecodeError, TimeoutError, ValueError) as exc:
        # Fail gracefully (return None) only for the expected network/parsing
        # failures: connectivity issues, HTTP errors, malformed JSON, timeouts,
        # and bad version strings. Genuine programming bugs (e.g. AttributeError,
        # TypeError) are intentionally NOT caught here so they surface instead of
        # being silently swallowed by a blanket `except Exception`.
        logger.debug("Update check skipped due to expected error: %s", exc)

    return None

if __name__ == "__main__":
    # Test script locally (use the current app version; see APP_VERSION in gui_app.py)
    print(check_for_update("3.0.0"))
