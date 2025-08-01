"""
Main entry point for SBOM Analyzer Flask application
"""

from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, port=5002) 