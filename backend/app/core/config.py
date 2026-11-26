"""
Application Configuration and Environment Settings.
"""
from pathlib import Path

class Settings:
    PROJECT_NAME: str = "Ransomware GNN Behavioral Detection System"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    
    # Base paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent.parent
    DATASET_DIR: Path = BASE_DIR / "datasets"
    CHECKPOINTS_DIR: Path = BASE_DIR / "ml" / "experiments" / "checkpoints"
    METRICS_DIR: Path = BASE_DIR / "ml" / "experiments" / "metrics"
    REPORTS_DIR: Path = BASE_DIR / "reports" / "generated"
    
    # Database
    DATABASE_URL: str = f"sqlite:///{BASE_DIR}/backend/ransomware_gnn.db"
    
    # Active GNN Model (gat, gcn, graphsage)
    DEFAULT_MODEL: str = "gat"
    
    # Risk policy thresholds
    RISK_THRESHOLD_PASS: float = 39.0   # <= 39: PASS
    RISK_THRESHOLD_WARN: float = 69.0   # 40 - 69: WARN
    RISK_THRESHOLD_BLOCK: float = 70.0  # >= 70: BLOCK
    
    # CORS
    CORS_ORIGINS: list = ["*"]

settings = Settings()
