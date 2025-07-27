#!/usr/bin/env python3
"""
Advanced Autonomous Malware Analyzer with Comprehensive Detection Capabilities
"""

import os
import sys
import time
import json
import tempfile
import logging
import hashlib
import re
import math
import statistics
import struct
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter, defaultdict
import subprocess

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

class AdvancedMalwareAnalyzer:
    """Comprehensive autonomous malware analyzer with deep inspection capabilities"""
    
    def __init__(self, config):
        self.config = config
        self.setup_logging()
        self.analysis_results = {}
        self.iteration_count = 0
        self.max_iterations = 15
        self.confidence_threshold = 0.85
        
        # Analysis categories
        self.analysis_categories = [
            'file_properties',
            'entropy_analysis', 
            'string_analysis',
            'crypto_analysis',
            'pe_analysis',
            'behavioral_patterns',
            'network_indicators',
            'persistence_mechanisms',
            'evasion_techniques',
            'code_analysis',
            'signature_generation'
        ]
        
        # Import AI orchestrator
        try:
            from ai.gemini_cli_integration import GeminiCLIOrchestrator
            self.ai_orchestrator = GeminiCLIOrchestrator(config)
        except ImportError as e:
            self.logger.warning(f"AI orchestrator not available: {e}")
            self.ai_orchestrator = None
    
    def setup_logging(self):
        """Setup comprehensive logging"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / f"malware_analysis_{int(time.time())}.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('AdvancedMalwareAnalyzer')
    
    def analyze_file_properties(self, file_path: str) -> Dict[str, Any]:
        """Analyze basic file properties"""
        self.logger.info("🔍 Analyzing file properties...")
        
        try:
            stat = os.stat(file_path)
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # File hashes
            md5_hash = hashlib.md5(file_data).hexdigest()
            sha1_hash = hashlib.sha1(file_data).hexdigest()
            sha256_hash = hashlib.sha256(file_data).hexdigest()
            
            # File type detection
            file_type = self.detect_file_type(file_data)
            magic_bytes = file_data[:16].hex()
            
            properties = {
                'file_path': file_path,
                'file_size': len(file_data),
                'creation_time': stat.st_ctime,
                'modification_time': stat.st_mtime,
                'md5': md5_hash,
                'sha1': sha1_hash,
                'sha256': sha256_hash,
                'file_type': file_type,
                'magic_bytes': magic_bytes,
                'is_executable': file_path.endswith(('.exe', '.dll', '.scr', '.com', '.bat', '.cmd', '.ps1')),
                'is_script': file_path.endswith(('.py', '.js', '.vbs', '.ps1', '.sh', '.bat', '.cmd'))
            }
            
            self.logger.info(f"✅ File properties analysis complete - Type: {file_type}, Size: {len(file_data)} bytes")
            return properties
            
        except Exception as e:
            self.logger.error(f"❌ File properties analysis failed: {e}")
            return {'error': str(e)}
    
    def analyze_entropy(self, file_path: str) -> Dict[str, Any]:
        """Comprehensive entropy analysis for packing detection"""
        self.logger.info("🔍 Analyzing file entropy...")
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            if not file_data:
                return {'error': 'Empty file'}
            
            # Overall entropy
            overall_entropy = self.calculate_shannon_entropy(file_data)
            
            # Block-based entropy analysis
            block_sizes = [256, 1024, 4096]
            block_entropies = {}
            
            for block_size in block_sizes:
                entropies = []
                for i in range(0, len(file_data) - block_size + 1, block_size):
                    block = file_data[i:i + block_size]
                    if block:
                        entropies.append(self.calculate_shannon_entropy(block))
                
                if entropies:
                    block_entropies[f'block_{block_size}'] = {
                        'mean': statistics.mean(entropies),
                        'stdev': statistics.stdev(entropies) if len(entropies) > 1 else 0,
                        'max': max(entropies),
                        'min': min(entropies),
                        'high_entropy_blocks': len([e for e in entropies if e > 7.0])
                    }
            
            # Packing detection
            packing_indicators = self.detect_packing(overall_entropy, block_entropies)
            
            entropy_analysis = {
                'overall_entropy': overall_entropy,
                'block_entropies': block_entropies,
                'packing_suspected': overall_entropy > 7.0,
                'packing_confidence': min(overall_entropy / 8.0, 1.0),
                'packing_indicators': packing_indicators
            }
            
            self.logger.info(f"✅ Entropy analysis complete - Overall: {overall_entropy:.2f}, Packing suspected: {entropy_analysis['packing_suspected']}")
            return entropy_analysis
            
        except Exception as e:
            self.logger.error(f"❌ Entropy analysis failed: {e}")
            return {'error': str(e)}
    
    def analyze_strings(self, file_path: str) -> Dict[str, Any]:
        """Comprehensive string analysis"""
        self.logger.info("🔍 Analyzing strings...")
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Extract ASCII strings
            ascii_strings = re.findall(rb'[\\x20-\\x7E]{4,}', file_data)
            
            # Extract Unicode strings
            unicode_strings = re.findall(rb'(?:[\\x20-\\x7E]\\x00){4,}', file_data)
            
            # Categorize strings
            string_categories = self.categorize_strings(ascii_strings)
            
            # Suspicious string detection
            suspicious_patterns = self.detect_suspicious_strings(ascii_strings)
            
            # API calls extraction
            api_calls = self.extract_api_calls(ascii_strings)
            
            string_analysis = {
                'total_ascii_strings': len(ascii_strings),
                'total_unicode_strings': len(unicode_strings),
                'string_categories': string_categories,
                'suspicious_patterns': suspicious_patterns,
                'api_calls': api_calls,
                'sample_strings': [s.decode('ascii', errors='ignore') for s in ascii_strings[:20]]
            }
            
            self.logger.info(f"✅ String analysis complete - ASCII: {len(ascii_strings)}, Suspicious: {len(suspicious_patterns)}")
            return string_analysis
            
        except Exception as e:
            self.logger.error(f"❌ String analysis failed: {e}")
            return {'error': str(e)}
    
    def analyze_crypto_patterns(self, file_path: str) -> Dict[str, Any]:
        """Analyze cryptographic patterns and constants"""
        self.logger.info("🔍 Analyzing cryptographic patterns...")
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Known crypto constants
            crypto_constants = {
                b'\\x67\\x45\\x23\\x01': 'MD5_INIT_A',
                b'\\xEF\\xCD\\xAB\\x89': 'MD5_INIT_B', 
                b'\\x98\\xBA\\xDC\\xFE': 'MD5_INIT_C',
                b'\\x10\\x32\\x54\\x76': 'MD5_INIT_D',
                b'\\x01\\x23\\x45\\x67': 'SHA1_INIT_H0',
                b'\\x89\\xAB\\xCD\\xEF': 'SHA1_INIT_H1',
                b'\\xFE\\xDC\\xBA\\x98': 'SHA1_INIT_H2',
                b'\\x76\\x54\\x32\\x10': 'SHA1_INIT_H3',
                b'\\xF0\\xE1\\xD2\\xC3': 'SHA1_INIT_H4'
            }
            
            found_constants = []
            for const, name in crypto_constants.items():
                if const in file_data:
                    found_constants.append(name)
            
            # XOR key detection
            xor_keys = self.detect_xor_keys(file_data)
            
            # Base64 patterns
            base64_patterns = re.findall(rb'[A-Za-z0-9+/]{20,}={0,2}', file_data)
            
            # Hex patterns
            hex_patterns = re.findall(rb'[0-9A-Fa-f]{32,}', file_data)
            
            crypto_analysis = {
                'crypto_constants': found_constants,
                'xor_keys': xor_keys,
                'base64_patterns': len(base64_patterns),
                'hex_patterns': len(hex_patterns),
                'encryption_suspected': len(found_constants) > 0 or len(xor_keys) > 0
            }
            
            self.logger.info(f"✅ Crypto analysis complete - Constants: {len(found_constants)}, XOR keys: {len(xor_keys)}")
            return crypto_analysis
            
        except Exception as e:
            self.logger.error(f"❌ Crypto analysis failed: {e}")
            return {'error': str(e)}
    
    def analyze_behavioral_patterns(self, file_path: str) -> Dict[str, Any]:
        """Analyze behavioral patterns in the code"""
        self.logger.info("🔍 Analyzing behavioral patterns...")
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Convert to string for pattern matching
            try:
                file_text = file_data.decode('utf-8', errors='ignore')
            except:
                file_text = str(file_data)
            
            behavioral_patterns = {
                'network_activity': self.detect_network_patterns(file_text),
                'file_operations': self.detect_file_operations(file_text),
                'registry_operations': self.detect_registry_operations(file_text),
                'process_operations': self.detect_process_operations(file_text),
                'persistence_mechanisms': self.detect_persistence_patterns(file_text),
                'evasion_techniques': self.detect_evasion_patterns(file_text),
                'crypto_operations': self.detect_crypto_operations(file_text)
            }
            
            # Calculate risk score
            risk_score = self.calculate_risk_score(behavioral_patterns)
            behavioral_patterns['risk_score'] = risk_score
            
            self.logger.info(f"✅ Behavioral analysis complete - Risk score: {risk_score:.2f}")
            return behavioral_patterns
            
        except Exception as e:
            self.logger.error(f"❌ Behavioral analysis failed: {e}")
            return {'error': str(e)}
    
    def request_best_effort_ai_analysis(self, analysis_state: Dict[str, Any], max_retries: int = 3) -> Dict[str, Any]:
        """Request AI-powered best-effort analysis, retrying and adapting on failure."""
        if not self.ai_orchestrator:
            return {'error': 'AI orchestrator not available'}
        last_error = None
        for attempt in range(1, max_retries + 1):
            self.logger.info(f"🤖 Requesting best-effort AI analysis (attempt {attempt})")
            prompt = f"""
You are an expert malware analyst with unlimited access to Python, shell, and macOS/Linux tools. Analyze the file in analysis_state['file_path'] using any method you deem best.

- You may import and install any Python package (pip) or system tool (brew).
- You may run shell commands (os.system, subprocess, etc.) and escalate to shell if Python fails.
- If a tool is missing, install it (pip or brew). If a method fails, try another. If you get an error, adapt and retry.
- Your goal is to provide the most accurate, detailed technical summary of what the file does, including all behaviors, side effects, and capabilities.
- The summary must be a human-readable, plain English paragraph (not just raw data), describing what the file does, its intent, and any suspicious or malicious actions. Include a clear behavioral breakdown (e.g., file writes, process launches, network activity, persistence, evasion, etc.).
- Always return a dictionary with all findings and a key 'technical_summary' (string) that summarizes what the file does in detail, in plain English.
- If you encounter an error, adapt your approach and try again. If you cannot analyze, explain why in 'technical_summary'.
- Return only executable Python code (no markdown, no comments, no docstrings).
- The code must be ready to execute as-is.

Current findings: {json.dumps(analysis_state, indent=2)}
{f'Previous error: {last_error}' if last_error else ''}
"""
            try:
                time.sleep(2)  # Rate limiting
                response = self.ai_orchestrator._execute_python_gemini(prompt)
                clean_code = self.clean_ai_code(response)
                if self.request_code_approval(f"AI Best-Effort Analysis (attempt {attempt})", clean_code):
                    result = self.execute_ai_code(clean_code, analysis_state)
                    # If result is a dict and has no 'error', or has a non-empty 'technical_summary', return it
                    if isinstance(result, dict) and ('error' not in result or attempt == max_retries):
                        return result
                    last_error = result.get('error', 'Unknown error') if isinstance(result, dict) else str(result)
                else:
                    self.logger.info(f"❌ AI analysis rejected by user")
                    return {'error': 'Code rejected by user'}
            except Exception as e:
                last_error = str(e)
                self.logger.error(f"❌ AI best-effort analysis failed: {e}")
        return {'error': f'All attempts failed. Last error: {last_error}'}
    
    def clean_ai_code(self, response: str) -> str:
        """Clean AI-generated code: remove markdown, comments, docstrings, and blank lines."""
        code = re.sub(r'```python\n?', '', response)
        code = re.sub(r'```\n?', '', code)
        code = re.sub(r'^```.*$', '', code, flags=re.MULTILINE)
        # Remove all comments and docstrings
        code = re.sub(r'(?m)^\s*#.*$', '', code)
        code = re.sub(r'""".*?"""', '', code, flags=re.DOTALL)
        code = re.sub(r"'''.*?'''", '', code, flags=re.DOTALL)
        # Remove blank lines
        code = '\n'.join([line for line in code.splitlines() if line.strip()])
        return code.strip()

    def request_code_approval(self, task_name: str, code: str) -> bool:
        """Request user approval for code execution"""
        print(f"\n🔍 APPROVAL REQUIRED FOR: {task_name}")
        print("=" * 60)
        print(code)
        print("=" * 60)
        print("\n⚠️  This code can import any library, run shell commands, and install packages if needed.")
        while True:
            choice = input("🤔 Approve this code? (y)es/(n)o/(s)how/(q)uit: ").lower().strip()
            if choice in ['y', 'yes']:
                print("✅ Code approved")
                return True
            elif choice in ['n', 'no']:
                print("❌ Code rejected")
                return False
            elif choice in ['s', 'show']:
                print("\n" + code)
            elif choice in ['q', 'quit']:
                print("🛑 Analysis terminated")
                sys.exit(0)
            else:
                print("Invalid choice. Use y/n/s/q")

    def execute_ai_code(self, code: str, analysis_state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute AI-generated code with full import and shell access (user approved)."""
        try:
            # Allow full builtins and imports
            exec_globals = {
                '__builtins__': __builtins__,
                'analysis_state': analysis_state,
                'os': os, 'sys': sys, 're': re, 'math': math,
                'hashlib': hashlib, 'struct': struct, 'json': json,
                'statistics': statistics, 'time': time,
                'subprocess': subprocess
            }
            exec(code, exec_globals)
            # Try main_analysis or any callable in exec_globals
            if 'main_analysis' in exec_globals and callable(exec_globals['main_analysis']):
                return exec_globals['main_analysis']()
            # Try ai_analysis or advanced_static_analysis
            for fn in ['ai_analysis', 'advanced_static_analysis', 'analyze', 'analyze_file']:
                if fn in exec_globals and callable(exec_globals[fn]):
                    return exec_globals[fn](analysis_state)
            # Try any callable
            for v in exec_globals.values():
                if callable(v):
                    try:
                        return v(analysis_state)
                    except Exception:
                        continue
            return {'error': 'No callable analysis function found'}
        except Exception as e:
            return {'error': str(e)}

    def analyze_file_autonomously(self, file_path: str) -> Dict[str, Any]:
        """Perform comprehensive autonomous analysis with adaptive AI best-effort phase."""
        self.logger.info(f"🚀 Starting autonomous analysis of {file_path}")
        analysis_state = {
            'file_path': file_path,
            'file_size': os.path.getsize(file_path),
            'analysis_timestamp': time.time()
        }
        # Phase 1: Core Analysis (optional, can be used as context)
        self.logger.info("📊 Phase 1: Core Analysis")
        core_analyses = {
            'file_properties': self.analyze_file_properties(file_path),
            'entropy_analysis': self.analyze_entropy(file_path),
            'string_analysis': self.analyze_strings(file_path),
            'crypto_analysis': self.analyze_crypto_patterns(file_path),
            'behavioral_patterns': self.analyze_behavioral_patterns(file_path)
        }
        # Phase 2: Adaptive AI Best-Effort Analysis
        self.logger.info("🤖 Phase 2: Adaptive AI Best-Effort Analysis")
        ai_result = self.request_best_effort_ai_analysis({**analysis_state, **core_analyses})
        # Phase 3: Final Assessment
        self.logger.info("📋 Phase 3: Final Assessment")
        all_results = {**core_analyses, 'ai_best_effort': ai_result}
        final_results = self.generate_comprehensive_report(all_results)
        return final_results
    
    def calculate_confidence(self, results: Dict[str, Any]) -> float:
        """Calculate analysis confidence"""
        factors = []
        
        # Number of successful analyses
        successful = len([r for r in results.values() if 'error' not in r])
        factors.append(min(successful / 8.0, 1.0))
        
        # Depth of analysis
        total_findings = sum(len(r) for r in results.values() if isinstance(r, dict) and 'error' not in r)
        factors.append(min(total_findings / 50.0, 1.0))
        
        # Threat indicators found
        threat_indicators = 0
        for result in results.values():
            if isinstance(result, dict):
                content = str(result).lower()
                if any(term in content for term in ['suspicious', 'malicious', 'threat', 'risk']):
                    threat_indicators += 1
        factors.append(min(threat_indicators / 5.0, 1.0))
        
        return sum(factors) / len(factors) if factors else 0.0
    
    def generate_comprehensive_report(self, all_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive analysis report"""
        threat_level = self.assess_threat_level(all_results)
        recommendations = self.generate_recommendations(all_results)
        iocs = self.extract_iocs(all_results)
        
        report = {
            'analysis_metadata': {
                'timestamp': time.time(),
                'analyzer_version': '2.0',
                'confidence_score': self.calculate_confidence(all_results)
            },
            'threat_assessment': {
                'threat_level': threat_level,
                'risk_score': self.calculate_overall_risk(all_results),
                'malware_family': self.classify_malware_family(all_results)
            },
            'detailed_analysis': all_results,
            'indicators_of_compromise': iocs,
            'recommendations': recommendations,
            'yara_rules': self.generate_yara_rules(all_results)
        }
        
        # Save report
        report_file = f"reports/comprehensive_analysis_{int(time.time())}.json"
        os.makedirs("reports", exist_ok=True)
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.logger.info(f"📊 Comprehensive report saved: {report_file}")
        return report
    
    # Helper methods
    def calculate_shannon_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def detect_file_type(self, data: bytes) -> str:
        """Detect file type from magic bytes"""
        if data.startswith(b'MZ'):
            return 'PE Executable'
        elif data.startswith(b'\\x7fELF'):
            return 'ELF Executable'
        elif data.startswith(b'\\xca\\xfe\\xba\\xbe'):
            return 'Mach-O Executable'
        elif data.startswith(b'PK'):
            return 'ZIP Archive'
        elif data.startswith(b'\\x50\\x4b\\x03\\x04'):
            return 'ZIP Archive'
        elif data.startswith(b'#!/'):
            return 'Script'
        else:
            return 'Unknown'
    
    def detect_packing(self, entropy: float, block_entropies: Dict) -> List[str]:
        """Detect packing indicators"""
        indicators = []
        
        if entropy > 7.5:
            indicators.append('High overall entropy suggests packing/encryption')
        
        for block_type, stats in block_entropies.items():
            if stats.get('high_entropy_blocks', 0) > 0:
                indicators.append(f'High entropy blocks detected in {block_type}')
        
        return indicators
    
    def categorize_strings(self, strings: List[bytes]) -> Dict[str, List[str]]:
        """Categorize extracted strings"""
        categories = defaultdict(list)
        
        for s in strings:
            try:
                decoded = s.decode('ascii', errors='ignore')
                if re.match(r'https?://', decoded):
                    categories['urls'].append(decoded)
                elif '\\\\' in decoded or '.exe' in decoded.lower():
                    categories['file_paths'].append(decoded)
                elif 'HKEY' in decoded or 'SOFTWARE' in decoded:
                    categories['registry_keys'].append(decoded)
                elif decoded.endswith(('A', 'W')) and len(decoded) > 3:
                    categories['api_calls'].append(decoded)
                else:
                    categories['other'].append(decoded)
            except:
                continue
        
        return dict(categories)
    
    def detect_suspicious_strings(self, strings: List[bytes]) -> List[str]:
        """Detect suspicious string patterns"""
        suspicious = []
        suspicious_patterns = [
            'malware', 'virus', 'trojan', 'backdoor', 'rootkit',
            'keylog', 'stealth', 'inject', 'hook', 'bypass',
            'decrypt', 'encrypt', 'payload', 'shellcode'
        ]
        
        for s in strings:
            try:
                decoded = s.decode('ascii', errors='ignore').lower()
                for pattern in suspicious_patterns:
                    if pattern in decoded:
                        suspicious.append(decoded)
                        break
            except:
                continue
        
        return suspicious[:10]  # Limit results
    
    def extract_api_calls(self, strings: List[bytes]) -> List[str]:
        """Extract potential API calls"""
        api_calls = []
        common_apis = [
            'CreateFile', 'WriteFile', 'ReadFile', 'CreateProcess',
            'VirtualAlloc', 'VirtualProtect', 'LoadLibrary', 'GetProcAddress',
            'RegOpenKey', 'RegSetValue', 'RegQueryValue', 'InternetOpen'
        ]
        
        for s in strings:
            try:
                decoded = s.decode('ascii', errors='ignore')
                for api in common_apis:
                    if api in decoded:
                        api_calls.append(decoded)
                        break
            except:
                continue
        
        return list(set(api_calls))[:20]  # Unique and limited
    
    def detect_xor_keys(self, data: bytes) -> List[Dict]:
        """Detect potential XOR keys"""
        xor_keys = []
        
        for key_len in range(1, min(17, len(data) // 4)):
            pattern = data[:key_len]
            count = data.count(pattern)
            if count > 3:
                xor_keys.append({
                    'key': pattern.hex(),
                    'length': key_len,
                    'occurrences': count
                })
        
        return xor_keys[:5]  # Limit results
    
    def detect_network_patterns(self, text: str) -> List[str]:
        """Detect network-related patterns"""
        patterns = []
        network_indicators = ['socket', 'connect', 'send', 'recv', 'http', 'tcp', 'udp', 'dns']
        
        for indicator in network_indicators:
            if indicator in text.lower():
                patterns.append(f'Network activity: {indicator}')
        
        return patterns
    
    def detect_file_operations(self, text: str) -> List[str]:
        """Detect file operation patterns"""
        patterns = []
        file_ops = ['open', 'read', 'write', 'delete', 'copy', 'move', 'create']
        
        for op in file_ops:
            if op in text.lower():
                patterns.append(f'File operation: {op}')
        
        return patterns
    
    def detect_registry_operations(self, text: str) -> List[str]:
        """Detect registry operation patterns"""
        patterns = []
        if 'registry' in text.lower() or 'hkey' in text.lower():
            patterns.append('Registry operations detected')
        
        return patterns
    
    def detect_process_operations(self, text: str) -> List[str]:
        """Detect process operation patterns"""
        patterns = []
        process_ops = ['process', 'thread', 'execute', 'spawn', 'fork']
        
        for op in process_ops:
            if op in text.lower():
                patterns.append(f'Process operation: {op}')
        
        return patterns
    
    def detect_persistence_patterns(self, text: str) -> List[str]:
        """Detect persistence mechanism patterns"""
        patterns = []
        persistence_indicators = ['startup', 'autostart', 'service', 'task', 'schedule']
        
        for indicator in persistence_indicators:
            if indicator in text.lower():
                patterns.append(f'Persistence mechanism: {indicator}')
        
        return patterns
    
    def detect_evasion_patterns(self, text: str) -> List[str]:
        """Detect evasion technique patterns"""
        patterns = []
        evasion_indicators = ['sleep', 'delay', 'debug', 'vm', 'sandbox', 'antivirus']
        
        for indicator in evasion_indicators:
            if indicator in text.lower():
                patterns.append(f'Evasion technique: {indicator}')
        
        return patterns
    
    def detect_crypto_operations(self, text: str) -> List[str]:
        """Detect cryptographic operation patterns"""
        patterns = []
        crypto_ops = ['encrypt', 'decrypt', 'hash', 'cipher', 'key', 'crypto']
        
        for op in crypto_ops:
            if op in text.lower():
                patterns.append(f'Crypto operation: {op}')
        
        return patterns
    
    def calculate_risk_score(self, behavioral_patterns: Dict) -> float:
        """Calculate risk score based on behavioral patterns"""
        risk_factors = 0
        total_patterns = sum(len(patterns) for patterns in behavioral_patterns.values() if isinstance(patterns, list))
        
        # Weight different categories
        weights = {
            'network_activity': 0.3,
            'persistence_mechanisms': 0.25,
            'evasion_techniques': 0.2,
            'crypto_operations': 0.15,
            'process_operations': 0.1
        }
        
        for category, patterns in behavioral_patterns.items():
            if isinstance(patterns, list) and patterns:
                weight = weights.get(category, 0.05)
                risk_factors += len(patterns) * weight
        
        return min(risk_factors, 10.0)  # Cap at 10
    
    def assess_threat_level(self, results: Dict) -> str:
        """Assess overall threat level"""
        risk_indicators = 0
        
        for result in results.values():
            if isinstance(result, dict):
                content = str(result).lower()
                if any(term in content for term in ['suspicious', 'malicious', 'threat', 'packed', 'encrypted']):
                    risk_indicators += 1
        
        if risk_indicators >= 4:
            return 'CRITICAL'
        elif risk_indicators >= 3:
            return 'HIGH'
        elif risk_indicators >= 1:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def calculate_overall_risk(self, results: Dict) -> float:
        """Calculate overall risk score"""
        risk_scores = []
        
        for result in results.values():
            if isinstance(result, dict) and 'risk_score' in result:
                risk_scores.append(result['risk_score'])
        
        return statistics.mean(risk_scores) if risk_scores else 0.0
    
    def classify_malware_family(self, results: Dict) -> str:
        """Attempt to classify malware family"""
        # Simple heuristic-based classification
        indicators = []
        
        for result in results.values():
            if isinstance(result, dict):
                content = str(result).lower()
                if 'trojan' in content:
                    indicators.append('Trojan')
                elif 'ransomware' in content or 'encrypt' in content:
                    indicators.append('Ransomware')
                elif 'backdoor' in content or 'c2' in content:
                    indicators.append('Backdoor')
                elif 'worm' in content or 'propagat' in content:
                    indicators.append('Worm')
        
        if indicators:
            return max(set(indicators), key=indicators.count)
        else:
            return 'Unknown'
    
    def extract_iocs(self, results: Dict) -> Dict[str, List]:
        """Extract indicators of compromise"""
        iocs = defaultdict(list)
        
        for result in results.values():
            if isinstance(result, dict):
                # Extract IPs
                content = str(result)
                ips = re.findall(r'\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b', content)
                iocs['ip_addresses'].extend(ips)
                
                # Extract domains
                domains = re.findall(r'\\b[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}\\b', content)
                iocs['domains'].extend(domains)
                
                # Extract file hashes
                if 'md5' in result:
                    iocs['md5_hashes'].append(result['md5'])
                if 'sha1' in result:
                    iocs['sha1_hashes'].append(result['sha1'])
                if 'sha256' in result:
                    iocs['sha256_hashes'].append(result['sha256'])
        
        # Remove duplicates
        for key in iocs:
            iocs[key] = list(set(iocs[key]))
        
        return dict(iocs)
    
    def generate_recommendations(self, results: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        for result in results.values():
            if isinstance(result, dict):
                content = str(result).lower()
                if 'high entropy' in content or 'packed' in content:
                    recommendations.append('Consider dynamic analysis in isolated environment')
                if 'network' in content:
                    recommendations.append('Monitor network traffic for C2 communication')
                if 'persistence' in content:
                    recommendations.append('Check startup locations and scheduled tasks')
                if 'registry' in content:
                    recommendations.append('Monitor registry modifications')
        
        return list(set(recommendations)) if recommendations else ['File appears benign based on current analysis']
    
    def generate_yara_rules(self, results: Dict) -> str:
        """Generate basic YARA rules"""
        rule_conditions = []
        
        # Add string-based conditions
        if 'string_analysis' in results and 'suspicious_patterns' in results['string_analysis']:
            for pattern in results['string_analysis']['suspicious_patterns'][:3]:
                rule_conditions.append(f'$s{len(rule_conditions)} = "{pattern}"')
        
        if rule_conditions:
            yara_rule = f"""
rule Generated_Malware_Rule {{
    meta:
        description = "Auto-generated rule from analysis"
        author = "AdvancedMalwareAnalyzer"
        date = "{time.strftime('%Y-%m-%d')}"
    
    strings:
        {chr(10).join('        ' + cond for cond in rule_conditions)}
    
    condition:
        any of them
}}
"""
        else:
            yara_rule = "// No suitable patterns found for YARA rule generation"
        
        return yara_rule

def main():
    """Main execution function"""
    print("🚀 Advanced Autonomous Malware Analyzer v2.0")
    print("=" * 60)
    

    import argparse
    parser = argparse.ArgumentParser(description="Advanced Autonomous Malware Analyzer")
    parser.add_argument('--file', '-f', type=str, help='Path to file to analyze')
    args = parser.parse_args()

    try:
        # Load configuration
        from utils.config import ConfigManager
        config = ConfigManager()
        analyzer = AdvancedMalwareAnalyzer(config)

        if args.file and os.path.isfile(args.file):
            file_to_analyze = args.file
            print(f"📄 Analyzing user-supplied file: {file_to_analyze}")
        else:
            # Prompt user for file path
            user_path = input("Enter path to file to analyze (leave blank to generate C binary): ").strip()
            if user_path and os.path.isfile(user_path):
                file_to_analyze = user_path
                print(f"📄 Analyzing user-supplied file: {file_to_analyze}")
            else:
                # Generate a C file, compile it, and analyze the binary
                c_code = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char *argv[]) {
    FILE *f = fopen("/tmp/testfile.txt", "w");
    if (f) {
        fprintf(f, "Malware test!\n");
        fclose(f);
    }
    system("whoami > /tmp/whoami.txt");
    printf("Hello from C malware!\n");
    return 0;
}
'''
                with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as cf:
                    cf.write(c_code)
                    c_path = cf.name
                bin_path = c_path[:-2]
                compile_cmd = f"gcc '{c_path}' -o '{bin_path}'"
                print(f"🛠️  Compiling C file: {c_path}")
                os.system(compile_cmd)
                if not os.path.isfile(bin_path):
                    print("❌ Failed to compile C file.")
                    return
                print(f"📄 Generated and compiled C binary: {bin_path}")
                file_to_analyze = bin_path
                print("\nWhat the C binary does:")
                print("- Writes 'Malware test!' to /tmp/testfile.txt")
                print("- Runs 'whoami' and writes output to /tmp/whoami.txt")
                print("- Prints 'Hello from C malware!' to stdout")

        print(f"\n🔍 Starting advanced autonomous analysis on: {file_to_analyze}")
        print("💡 This analyzer performs comprehensive malware analysis with AI assistance")
        results = analyzer.analyze_file_autonomously(file_to_analyze)

        print("\n" + "="*60)
        print("📋 COMPREHENSIVE ANALYSIS COMPLETE!")
        print("="*60)
        metadata = results['analysis_metadata']
        threat = results['threat_assessment']
        print(f"✅ Analysis confidence: {metadata['confidence_score']:.2f}")
        print(f"⚠️  Threat level: {threat['threat_level']}")
        print(f"🎯 Risk score: {threat['risk_score']:.2f}")
        print(f"🦠 Malware family: {threat['malware_family']}")
        print("\n📊 Analysis Categories Completed:")
        for category, result in results['detailed_analysis'].items():
            status = "✅" if 'error' not in result else "❌"
            print(f"  {status} {category}")
        print("\n🚨 Indicators of Compromise:")
        iocs = results['indicators_of_compromise']
        for ioc_type, values in iocs.items():
            if values:
                print(f"  📍 {ioc_type}: {len(values)} found")
        print("\n💡 Security Recommendations:")
        for i, rec in enumerate(results['recommendations'][:5], 1):
            print(f"  {i}. {rec}")
        print(f"\n📄 Generated YARA Rule:")
        print(results['yara_rules'])
        # Show technical summary if available
        for k, v in results['detailed_analysis'].items():
            if isinstance(v, dict) and 'technical_summary' in v:
                print(f"\n📝 AI Technical Summary for {k}:")
                print(v['technical_summary'])
        # Cleanup temp files
        if 'c_path' in locals() and os.path.isfile(c_path):
            os.unlink(c_path)
        if 'bin_path' in locals() and os.path.isfile(bin_path):
            os.unlink(bin_path)
    except KeyboardInterrupt:
        print("\n🛑 Analysis interrupted by user")
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
