"""
Synthetic API Call Behavior Trace Generator.
Simulates realistic, safe, and ethically sound Windows API call traces
modeled after real ransomware kill-chains (GraphShield, RansoGuard, Lin et al.)
without executing or containing any destructive code.
"""
import random
import hashlib
import json
from pathlib import Path
from typing import List, Dict, Any
from ml.data.schema import ApiCallEvent, ApiTrace, TraceMetadata
from ml.preprocessing.sensitive_api import get_api_category, is_pre_attack_sensitive

class SyntheticTraceGenerator:
    """
    Generates synthetic dynamic API call traces with verified labels,
    realistic temporal spacing, multi-threading, and sanitized arguments.
    """
    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def _generate_sha256(self, name: str) -> str:
        return hashlib.sha256(f"{name}_{self.rng.random()}".encode()).hexdigest()

    def generate_benign_trace(self, sample_idx: int) -> ApiTrace:
        families = [
            "Benign-BuildTool",
            "Benign-CompilerWorker",
            "Benign-DocViewer",
            "Benign-DatabaseAgent",
            "Benign-SystemMonitor"
        ]
        family = self.rng.choice(families)
        sample_id = f"BENIGN_{sample_idx:04d}_{family}"
        events: List[ApiCallEvent] = []
        t = 0.0
        pid = self.rng.randint(2000, 8000)
        main_tid = self.rng.randint(100, 500)

        # Stage 1: Runtime Initialization
        init_apis = [
            ("GetSystemTime", {"format": "UTC"}),
            ("GetModuleHandle", {"module": "kernel32.dll"}),
            ("GetProcAddress", {"symbol": "VirtualAlloc"}),
            ("LoadLibrary", {"path": "advapi32.dll"}),
            ("GetSystemInfo", {"arch": "x64", "cores": 8}),
            ("VirtualAlloc", {"size": 65536, "protection": "PAGE_READWRITE"})
        ]
        for api, args in init_apis:
            t += self.rng.uniform(1.5, 8.0)
            events.append(ApiCallEvent(
                call_index=len(events),
                timestamp_ms=round(t, 2),
                process_id=pid,
                process_name=f"{family.lower()}.exe",
                thread_id=main_tid,
                api_name=api,
                category=get_api_category(api),
                arguments=args,
                return_value="SUCCESS",
                is_sensitive=is_pre_attack_sensitive(api)
            ))

        # Stage 2: Normal File Operations (Reading configs or project source)
        num_files = self.rng.randint(4, 10)
        for f_idx in range(num_files):
            filename = f"<USER_PROFILE>\\project\\source_module_{f_idx}.dat"
            file_ops = [
                ("CreateFile", {"path": filename, "access": "GENERIC_READ", "creation": "OPEN_EXISTING"}),
                ("ReadFile", {"path": filename, "bytes_requested": 4096}),
                ("CloseHandle", {"handle": f"0x{self.rng.randint(1000, 9999):x}"}),
                ("Sleep", {"duration_ms": self.rng.randint(10, 50)})
            ]
            for api, args in file_ops:
                t += self.rng.uniform(2.0, 15.0)
                events.append(ApiCallEvent(
                    call_index=len(events),
                    timestamp_ms=round(t, 2),
                    process_id=pid,
                    process_name=f"{family.lower()}.exe",
                    thread_id=main_tid,
                    api_name=api,
                    category=get_api_category(api),
                    arguments=args,
                    return_value="SUCCESS",
                    is_sensitive=is_pre_attack_sensitive(api)
                ))

        # Stage 3: Normal network telemetry / update check (benign)
        if self.rng.random() > 0.4:
            net_ops = [
                ("WSAStartup", {"version": "2.2"}),
                ("connect", {"endpoint": "repo.internal.corp:443"}),
                ("send", {"payload_type": "HTTP_GET_METADATA"}),
                ("recv", {"status": "200_OK"}),
                ("closesocket", {"status": "CLEAN"})
            ]
            for api, args in net_ops:
                t += self.rng.uniform(5.0, 25.0)
                events.append(ApiCallEvent(
                    call_index=len(events),
                    timestamp_ms=round(t, 2),
                    process_id=pid,
                    process_name=f"{family.lower()}.exe",
                    thread_id=main_tid,
                    api_name=api,
                    category=get_api_category(api),
                    arguments=args,
                    return_value="SUCCESS",
                    is_sensitive=is_pre_attack_sensitive(api)
                ))

        # Final cleanup
        events.append(ApiCallEvent(
            call_index=len(events),
            timestamp_ms=round(t + 10.0, 2),
            process_id=pid,
            process_name=f"{family.lower()}.exe",
            thread_id=main_tid,
            api_name="ExitProcess",
            category=get_api_category("ExitProcess"),
            arguments={"exit_code": 0},
            return_value="SUCCESS",
            is_sensitive=False
        ))

        meta = TraceMetadata(
            sample_id=sample_id,
            sha256=self._generate_sha256(sample_id),
            platform="windows",
            architecture="x64",
            label="benign",
            label_id=0,
            family=family,
            is_synthetic=True,
            collection_source="Dynamic-Trace-Simulation-Engine",
            total_calls=len(events),
            duration_ms=round(events[-1].timestamp_ms, 2)
        )
        return ApiTrace(metadata=meta, events=events)

    def generate_suspicious_trace(self, sample_idx: int) -> ApiTrace:
        families = [
            "Suspicious-ReconTool",
            "Suspicious-ProcessInjector",
            "Suspicious-PersistScript",
            "Suspicious-NetworkScanner"
        ]
        family = self.rng.choice(families)
        sample_id = f"SUSP_{sample_idx:04d}_{family}"
        events: List[ApiCallEvent] = []
        t = 0.0
        pid = self.rng.randint(2000, 8000)
        tid = self.rng.randint(100, 500)

        # Stage 1: Extensive discovery
        recon_calls = [
            ("GetSystemInfo", {"arch": "x64", "processors": 16}),
            ("IsDebuggerPresent", {}),
            ("GetComputerName", {}),
            ("GetLogicalDrives", {"mask": "0x3F"}),
            ("RegOpenKeyEx", {"root": "HKLM", "subkey": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"}),
            ("RegSetValueEx", {"value_name": "SysTask", "data": "<USER_PROFILE>\\helper.exe"}),
            ("RegCloseKey", {})
        ]
        for api, args in recon_calls:
            t += self.rng.uniform(2.0, 10.0)
            events.append(ApiCallEvent(
                call_index=len(events),
                timestamp_ms=round(t, 2),
                process_id=pid,
                process_name="susp_tool.exe",
                thread_id=tid,
                api_name=api,
                category=get_api_category(api),
                arguments=args,
                return_value="SUCCESS",
                is_sensitive=is_pre_attack_sensitive(api)
            ))

        # Stage 2: Suspicious Memory Injection or Process Tampering
        inj_calls = [
            ("OpenProcess", {"target_pid": 1204, "desired_access": "PROCESS_ALL_ACCESS"}),
            ("VirtualAllocEx", {"target_pid": 1204, "size": 8192, "protection": "PAGE_EXECUTE_READWRITE"}),
            ("WriteProcessMemory", {"target_pid": 1204, "bytes": 4096}),
            ("CreateRemoteThread", {"target_pid": 1204, "start_address": "0x7ffa0000"})
        ]
        for api, args in inj_calls:
            t += self.rng.uniform(5.0, 20.0)
            events.append(ApiCallEvent(
                call_index=len(events),
                timestamp_ms=round(t, 2),
                process_id=pid,
                process_name="susp_tool.exe",
                thread_id=tid,
                api_name=api,
                category=get_api_category(api),
                arguments=args,
                return_value="SUCCESS",
                is_sensitive=is_pre_attack_sensitive(api)
            ))

        # Network beacon
        net_calls = [
            ("WSAStartup", {}),
            ("connect", {"endpoint": "<REMOTE_IP>:8080"}),
            ("send", {"bytes": 256, "encrypted": False}),
            ("closesocket", {})
        ]
        for api, args in net_calls:
            t += self.rng.uniform(10.0, 30.0)
            events.append(ApiCallEvent(
                call_index=len(events),
                timestamp_ms=round(t, 2),
                process_id=pid,
                process_name="susp_tool.exe",
                thread_id=tid,
                api_name=api,
                category=get_api_category(api),
                arguments=args,
                return_value="SUCCESS",
                is_sensitive=is_pre_attack_sensitive(api)
            ))

        meta = TraceMetadata(
            sample_id=sample_id,
            sha256=self._generate_sha256(sample_id),
            platform="windows",
            architecture="x64",
            label="suspicious",
            label_id=1,
            family=family,
            is_synthetic=True,
            collection_source="Dynamic-Trace-Simulation-Engine",
            total_calls=len(events),
            duration_ms=round(events[-1].timestamp_ms, 2)
        )
        return ApiTrace(metadata=meta, events=events)

    def generate_ransomware_trace(self, sample_idx: int) -> ApiTrace:
        families = [
            "LockBit3-Sim",
            "WannaCry-Sim",
            "Conti-Sim",
            "BlackCat-Sim",
            "Phobos-Sim"
        ]
        family = self.rng.choice(families)
        sample_id = f"RANSOM_{sample_idx:04d}_{family}"
        events: List[ApiCallEvent] = []
        t = 0.0
        pid = self.rng.randint(2000, 8000)
        main_tid = self.rng.randint(100, 500)
        worker_tid = main_tid + 1

        # Phase 1: Environment Discovery & Anti-Debugging (PASAC early indicators)
        phase1_apis = [
            ("IsDebuggerPresent", {}),
            ("CheckRemoteDebuggerPresent", {}),
            ("GetComputerName", {}),
            ("GetSystemInfo", {"arch": "x64"}),
            ("GetLogicalDrives", {"mask": "0x3F"}),
            ("GetDriveType", {"drive": "C:\\"}),
            ("GetDriveType", {"drive": "D:\\"}),
            ("GetDriveType", {"drive": "Z:\\"})
        ]
        for api, args in phase1_apis:
            t += self.rng.uniform(1.0, 5.0)
            events.append(ApiCallEvent(
                call_index=len(events),
                timestamp_ms=round(t, 2),
                process_id=pid,
                process_name=f"{family.lower()}.exe",
                thread_id=main_tid,
                api_name=api,
                category=get_api_category(api),
                arguments=args,
                return_value="SUCCESS",
                is_sensitive=is_pre_attack_sensitive(api)
            ))

        # Phase 2: Defense Evasion & Shadow Copy Deletion (Inhibiting System Recovery)
        phase2_apis = [
            ("ShellExecute", {"file": "vssadmin.exe", "parameters": "delete shadows /all /quiet", "show": "SW_HIDE"}),
            ("CreateProcess", {"app": "bcdedit.exe", "cmdline": "/set {default} recoveryenabled No"}),
            ("CreateProcess", {"app": "wbadmin.exe", "cmdline": "delete catalog -quiet"}),
            ("RegOpenKeyEx", {"root": "HKLM", "subkey": "SYSTEM\\CurrentControlSet\\Services"}),
            ("RegSetValueEx", {"value_name": "DisableMonitoring", "data": "1"})
        ]
        for api, args in phase2_apis:
            t += self.rng.uniform(3.0, 15.0)
            events.append(ApiCallEvent(
                call_index=len(events),
                timestamp_ms=round(t, 2),
                process_id=pid,
                process_name=f"{family.lower()}.exe",
                thread_id=main_tid,
                api_name=api,
                category=get_api_category(api),
                arguments=args,
                return_value="SUCCESS",
                is_sensitive=is_pre_attack_sensitive(api)
            ))

        # Phase 3: Cryptographic Initialization & C2 Key Exfiltration
        phase3_apis = [
            ("CryptAcquireContext", {"provider": "PROV_RSA_AES", "flags": "CRYPT_VERIFYCONTEXT"}),
            ("CryptGenRandom", {"bytes": 32}),
            ("CryptGenKey", {"alg_id": "CALG_AES_256"}),
            ("CryptExportKey", {"key_blob": "<MASTER_PUBLIC_KEY>"}),
            ("WSAStartup", {}),
            ("connect", {"endpoint": "<REMOTE_IP>:443"}),
            ("send", {"payload_type": "EXFILTRATE_SESSION_KEY", "size": 512}),
            ("closesocket", {})
        ]
        for api, args in phase3_apis:
            t += self.rng.uniform(2.0, 8.0)
            events.append(ApiCallEvent(
                call_index=len(events),
                timestamp_ms=round(t, 2),
                process_id=pid,
                process_name=f"{family.lower()}.exe",
                thread_id=main_tid,
                api_name=api,
                category=get_api_category(api),
                arguments=args,
                return_value="SUCCESS",
                is_sensitive=is_pre_attack_sensitive(api)
            ))

        # Phase 4: Rapid Traversal & Mass Cryptographic File Transformation
        events.append(ApiCallEvent(
            call_index=len(events),
            timestamp_ms=round(t + 2.0, 2),
            process_id=pid,
            process_name=f"{family.lower()}.exe",
            thread_id=main_tid,
            api_name="FindFirstFile",
            category=get_api_category("FindFirstFile"),
            arguments={"path": "<USER_PROFILE>\\Documents\\*"},
            return_value="VALID_HANDLE",
            is_sensitive=True
        ))
        t += 3.0

        target_extensions = [".docx", ".pdf", ".xlsx", ".sql", ".jpg", ".zip", ".cpp"]
        encrypted_extension = f".{family.split('-')[0].lower()}"

        num_target_files = self.rng.randint(12, 22)
        for i in range(num_target_files):
            ext = self.rng.choice(target_extensions)
            orig_name = f"<USER_PROFILE>\\Documents\\financial_record_{i}{ext}"
            locked_name = f"{orig_name}{encrypted_extension}"

            burst = [
                ("FindNextFile", {"next_file": orig_name}),
                ("CreateFile", {"path": orig_name, "access": "GENERIC_READ | GENERIC_WRITE", "mode": "OPEN_EXISTING"}),
                ("ReadFile", {"path": orig_name, "bytes": 65536}),
                ("CryptEncrypt", {"alg": "AES_256", "block_size": 16}),
                ("WriteFile", {"path": orig_name, "bytes": 65536}),
                ("MoveFileEx", {"source": orig_name, "destination": locked_name, "flags": "MOVEFILE_REPLACE_EXISTING"}),
                ("SetFileAttributes", {"path": locked_name, "attributes": "FILE_ATTRIBUTE_HIDDEN"}),
                ("CloseHandle", {})
            ]
            for api, args in burst:
                t += self.rng.uniform(0.5, 3.0) # High-velocity loop
                events.append(ApiCallEvent(
                    call_index=len(events),
                    timestamp_ms=round(t, 2),
                    process_id=pid,
                    process_name=f"{family.lower()}.exe",
                    thread_id=worker_tid,
                    api_name=api,
                    category=get_api_category(api),
                    arguments=args,
                    return_value="SUCCESS",
                    is_sensitive=is_pre_attack_sensitive(api)
                ))

        # Phase 5: Ransom Note Generation & System Lock Notification
        note_name = f"<USER_PROFILE>\\Desktop\\README_RESTORE_FILES_{family.split('-')[0]}.txt"
        phase5_apis = [
            ("CreateFile", {"path": note_name, "access": "GENERIC_WRITE", "mode": "CREATE_ALWAYS"}),
            ("WriteFile", {"path": note_name, "text": "YOUR FILES HAVE BEEN ENCRYPTED! CONTACT DECRYPTOR TEAM."}),
            ("CloseHandle", {}),
            ("ShellExecute", {"file": "notepad.exe", "parameters": note_name, "show": "SW_SHOW"}),
            ("RegSetValueEx", {"subkey": "Control Panel\\Desktop", "value_name": "Wallpaper", "data": "ransom_note.bmp"})
        ]
        for api, args in phase5_apis:
            t += self.rng.uniform(4.0, 12.0)
            events.append(ApiCallEvent(
                call_index=len(events),
                timestamp_ms=round(t, 2),
                process_id=pid,
                process_name=f"{family.lower()}.exe",
                thread_id=main_tid,
                api_name=api,
                category=get_api_category(api),
                arguments=args,
                return_value="SUCCESS",
                is_sensitive=is_pre_attack_sensitive(api)
            ))

        meta = TraceMetadata(
            sample_id=sample_id,
            sha256=self._generate_sha256(sample_id),
            platform="windows",
            architecture="x64",
            label="ransomware",
            label_id=2,
            family=family,
            is_synthetic=True,
            collection_source="Dynamic-Trace-Simulation-Engine",
            total_calls=len(events),
            duration_ms=round(events[-1].timestamp_ms, 2)
        )
        return ApiTrace(metadata=meta, events=events)

    def generate_batch(self, n_benign: int = 100, n_suspicious: int = 50, n_ransomware: int = 100) -> List[ApiTrace]:
        """Generates a balanced or representative research corpus."""
        dataset: List[ApiTrace] = []
        for i in range(n_benign):
            dataset.append(self.generate_benign_trace(i + 1))
        for i in range(n_suspicious):
            dataset.append(self.generate_suspicious_trace(i + 1))
        for i in range(n_ransomware):
            dataset.append(self.generate_ransomware_trace(i + 1))
        self.rng.shuffle(dataset)
        return dataset

    def export_dataset(self, dataset: List[ApiTrace], output_dir: Path):
        """Saves traces into JSON format and generates CSV overview."""
        output_dir.mkdir(parents=True, exist_ok=True)
        overview_records = []

        for trace in dataset:
            class_folder = output_dir / trace.metadata.label
            class_folder.mkdir(parents=True, exist_ok=True)
            file_path = class_folder / f"{trace.metadata.sample_id}.json"
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(trace.model_dump(), f, indent=2)

            overview_records.append({
                "sample_id": trace.metadata.sample_id,
                "sha256": trace.metadata.sha256,
                "label": trace.metadata.label,
                "label_id": trace.metadata.label_id,
                "family": trace.metadata.family,
                "total_calls": trace.metadata.total_calls,
                "duration_ms": trace.metadata.duration_ms,
                "is_synthetic": trace.metadata.is_synthetic,
                "file_path": str(file_path.relative_to(output_dir))
            })

        summary_file = output_dir / "dataset_summary.json"
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump({
                "total_samples": len(dataset),
                "counts": {
                    "benign": sum(1 for d in dataset if d.metadata.label == "benign"),
                    "suspicious": sum(1 for d in dataset if d.metadata.label == "suspicious"),
                    "ransomware": sum(1 for d in dataset if d.metadata.label == "ransomware"),
                },
                "samples": overview_records
            }, f, indent=2)
