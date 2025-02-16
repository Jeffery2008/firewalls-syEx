try:
    from typing import Dict
    print("Typing module imported successfully")
except ImportError as e:
    print(f"ImportError: {e}")
except Exception as e:
    print(f"Other error: {e}")
