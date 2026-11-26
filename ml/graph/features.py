"""
Node and Edge Feature Encoders for API Call Graphs.
Produces standardized, normalized numerical tensors for GNN ingestion.
"""
from typing import Dict, List, Tuple
import numpy as np
import torch
from ml.data.schema import ApiCallEvent, ApiTrace
from ml.preprocessing.sensitive_api import CATEGORY_LIST, CANONICAL_NAME_MAP

# Standard Windows API vocabulary for consistent encoding
API_VOCABULARY: List[str] = [
    "<PAD>", "<UNK>",
    "CreateFile", "ReadFile", "WriteFile", "DeleteFile", "SetFileAttributes", "MoveFileEx",
    "FindFirstFile", "FindNextFile", "FindClose", "GetLogicalDrives", "GetDriveType",
    "CryptAcquireContext", "CryptGenKey", "CryptGenRandom", "CryptEncrypt", "CryptDecrypt",
    "CryptExportKey", "CryptImportKey", "BCryptOpenAlgorithmProvider", "BCryptEncrypt",
    "OpenProcess", "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory",
    "ReadProcessMemory", "CreateRemoteThread", "TerminateProcess", "HeapAlloc", "VirtualFree",
    "RegOpenKeyEx", "RegSetValueEx", "RegCreateKeyEx", "RegDeleteKey", "RegCloseKey",
    "OpenSCManager", "CreateService", "StartService",
    "ShellExecute", "CreateProcess", "WinExec",
    "WSAStartup", "socket", "connect", "send", "recv", "closesocket",
    "InternetOpen", "HttpOpenRequest", "HttpSendRequest", "InternetReadFile",
    "GetSystemInfo", "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetComputerName",
    "GlobalMemoryStatusEx", "GetSystemTime", "GetModuleHandle", "GetProcAddress",
    "LoadLibrary", "Sleep", "CloseHandle", "ExitProcess"
]

API_TO_IDX: Dict[str, int] = {name: i for i, name in enumerate(API_VOCABULARY)}
CATEGORY_TO_IDX: Dict[str, int] = {cat: i for i, cat in enumerate(CATEGORY_LIST)}

NODE_FEATURE_DIM = 1 + len(CATEGORY_LIST) + 1 + 1 + 1 + 1  # 1 (api_id_norm) + 9 (cat) + 1 (freq) + 1 (time) + 1 (sens) + 1 (thread) = 14
EDGE_FEATURE_DIM = 2  # [time_delta_norm, edge_type_norm]

class FeatureEncoder:
    """Encodes API call event sequences into numerical graph feature tensors."""

    @staticmethod
    def encode_node(event: ApiCallEvent, total_events: int, max_duration: float, api_freq: float) -> np.ndarray:
        features = np.zeros(NODE_FEATURE_DIM, dtype=np.float32)
        
        # 1. API Vocabulary ID (normalized)
        canon = CANONICAL_NAME_MAP.get(event.api_name, event.api_name)
        vocab_idx = API_TO_IDX.get(canon, API_TO_IDX["<UNK>"])
        features[0] = vocab_idx / len(API_VOCABULARY)
        
        # 2. One-hot Category Encoding (dim 1 to 9)
        cat_idx = CATEGORY_TO_IDX.get(event.category, len(CATEGORY_LIST) - 1)
        features[1 + cat_idx] = 1.0
        
        # 3. Relative Call Frequency (normalized across trace)
        features[10] = api_freq
        
        # 4. Normalized Timestamp in Trace
        norm_time = (event.timestamp_ms / max_duration) if max_duration > 0 else 0.0
        features[11] = min(1.0, max(0.0, norm_time))
        
        # 5. PASAC Pre-Attack Sensitive Indicator
        features[12] = 1.0 if event.is_sensitive else 0.0
        
        # 6. Thread Identifier representation (mod 10 normalized)
        features[13] = (event.thread_id % 10) / 10.0
        
        return features

    @staticmethod
    def encode_edge(time_delta_ms: float, edge_type: int) -> np.ndarray:
        """
        Encodes edge features:
        edge_type: 0 = Sequential temporal transition, 1 = Intra-thread continuity, 2 = Resource dependency
        """
        features = np.zeros(EDGE_FEATURE_DIM, dtype=np.float32)
        # Normalize delta ms: log-scale compression
        features[0] = np.log1p(max(0.0, time_delta_ms)) / 10.0
        features[1] = edge_type / 2.0
        return features
