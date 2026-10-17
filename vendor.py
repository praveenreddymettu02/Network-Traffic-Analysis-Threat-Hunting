import os
import urllib.request

# URLs and destination paths
FILES = [
    (
        "https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/"
        "bootstrap.min.css",
        "static/vendor/bootstrap.min.css",
    ),
    (
        "https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/"
        "bootstrap.min.js",
        "static/vendor/bootstrap.min.js",
    ),
    (
        "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/"
        "chart.umd.min.js",
        "static/vendor/chart.min.js",
    ),
    (
        "https://cdn.plot.ly/plotly-2.27.0.min.js",
        "static/vendor/plotly-latest.min.js",
    ),
]


def download_files():
    # Create vendor folder if missing
    os.makedirs("static/vendor", exist_ok=True)

    for url, dest in FILES:
        print(f"Downloading {dest}...")
        try:
            urllib.request.urlretrieve(url, dest)
            print(f"✓ {dest} downloaded.")
        except Exception as e:
            print(f"✗ Failed: {e}")

    print("\n✅ All vendor files are ready. You can now run 'python app.py'")


if __name__ == "__main__":
    download_files()
