# File: blockchain_project/run.py
from app import create_app

if __name__ == "__main__":
    app_instance = create_app()
    app_instance.run(host='0.0.0.0', port=5000, debug=True)

    
    
