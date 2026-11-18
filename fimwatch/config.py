from dataclasses import dataclass

@dataclass
class Config:
    burst_window_seconds: int = 10
    burst_event_threshold: int = 30
    unique_file_threshold: int = 20
    high_burst_threshold: int = 100
    delete_rename_ratio_threshold: float = 0.35
    extension_change_threshold: int = 10
    max_process_candidates: int = 8
    hash_chunk_size: int = 1024 * 1024
