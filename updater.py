import urllib.request
import json

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
                
            # Semantic version comparison
            current_parts = [int(x) for x in current_version.split(".") if x.isdigit()]
            latest_parts = [int(x) for x in latest_version.split(".") if x.isdigit()]
            
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
                
    except Exception:
        # Silently catch all URLError, HTTPError, JSONDecodeError, timeout, etc.
        pass
        
    return None

if __name__ == "__main__":
    # Test script locally
    print(check_for_update("2.1.0"))
