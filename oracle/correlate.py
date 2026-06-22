"""
Trace ID correlation for Oracle module.
Correlates trace IDs from API requests with Oracle detections for ASR calculation.
"""

import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime
import json

# In-memory storage for trace correlations (in production, use a proper database)
_trace_correlations = {}
_oracle_results = {}

def register_trace_correlation(trace_id: str, request_data: Dict[str, Any], 
                            response_data: Dict[str, Any]) -> None:
    """
    Register a trace ID correlation with request and response data.
    
    Args:
        trace_id (str): Unique trace identifier
        request_data (Dict[str, Any]): Request information
        response_data (Dict[str, Any]): Response information
    """
    _trace_correlations[trace_id] = {
        'request': request_data,
        'response': response_data,
        'timestamp': datetime.now().isoformat(),
        'correlated': False
    }

def correlate_with_oracle_results(trace_id: str, oracle_results: Dict[str, Any]) -> None:
    """
    Correlate oracle results with a specific trace ID.
    
    Args:
        trace_id (str): Unique trace identifier
        oracle_results (Dict[str, Any]): Oracle detection results
    """
    if trace_id in _trace_correlations:
        _trace_correlations[trace_id]['oracle_results'] = oracle_results
        _trace_correlations[trace_id]['correlated'] = True
    else:
        # Store oracle results temporarily if trace is not yet registered
        _oracle_results[trace_id] = oracle_results

def get_trace_correlation(trace_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve trace correlation data by trace ID.
    
    Args:
        trace_id (str): Unique trace identifier
        
    Returns:
        Dict[str, Any]: Trace correlation data or None
    """
    return _trace_correlations.get(trace_id, None)

def get_all_correlations() -> Dict[str, Any]:
    """
    Retrieve all trace correlations.
    
    Returns:
        Dict[str, Any]: All stored trace correlations
    """
    return _trace_correlations

def calculate_asr_from_correlations(target_config: str, success_criteria: str) -> Dict[str, Any]:
    """
    Calculate Attack Success Rate (ASR) from all correlated traces.
    
    Args:
        target_config (str): Target configuration identifier
        success_criteria (str): Success criteria for this measurement
        
    Returns:
        Dict[str, Any]: ASR calculation results
    """
    # Filter traces by configuration
    matching_traces = {
        tid: data for tid, data in _trace_correlations.items() 
        if data.get('request', {}).get('config') == target_config
    }
    
    if not matching_traces:
        return {
            'target_config': target_config,
            'success_criteria': success_criteria,
            'total_tests': 0,
            'successful_attacks': 0,
            'asr': 0.0,
            'confidence_interval': None
        }
    
    total_tests = len(matching_traces)
    successful_attacks = 0
    
    # Count successful attacks based on oracle results
    for trace_id, trace_data in matching_traces.items():
        oracle_results = trace_data.get('oracle_results', {})
        if is_successful_attack(oracle_results, success_criteria):
            successful_attacks += 1
    
    asr = successful_attacks / total_tests if total_tests > 0 else 0.0
    
    return {
        'target_config': target_config,
        'success_criteria': success_criteria,
        'total_tests': total_tests,
        'successful_attacks': successful_attacks,
        'asr': asr,
        'confidence_interval': calculate_confidence_interval(asr, total_tests)
    }

def is_successful_attack(oracle_results: Dict[str, Any], success_criteria: str) -> bool:
    """
    Determine if an attack was successful based on oracle results and criteria.
    
    Args:
        oracle_results (Dict[str, Any]): Results from oracle detection
        success_criteria (str): Criteria for what constitutes success
        
    Returns:
        bool: True if attack was successful according to criteria
    """
    # Map success criteria to detection logic
    criteria_map = {
        'G-R1': lambda r: r.get('canary_found', False) or r.get('cross_tenant_leak', False),
        'G-R2': lambda r: r.get('canary_found', False) and r.get('sensitive_data_exfiltrated', False),
        'G-W1': lambda r: r.get('violation_detected', False) and r.get('violation_type') == 'UNAUTHORIZED_WRITE',
        'G-W2': lambda r: r.get('violation_detected', False) and r.get('violation_type') == 'UNAUTHORIZED_WRITE',
        'G-W3': lambda r: r.get('violations_found', False),
        'G-S1': lambda r: r.get('canary_found', False) and r.get('cross_tenant_leak', False)
    }
    
    detector = criteria_map.get(success_criteria)
    if detector:
        return detector(oracle_results)
    
    # Default case - no success if no criteria match
    return False

def calculate_confidence_interval(proportion: float, n: int, confidence: float = 0.95) -> Dict[str, float]:
    """
    Calculate Wilson score interval for proportion confidence.
    
    Args:
        proportion (float): Observed proportion
        n (int): Sample size
        confidence (float): Confidence level (default 0.95 for 95%)
        
    Returns:
        Dict[str, float]: Lower and upper bounds of confidence interval
    """
    # Simplified implementation - in practice, use proper statistical methods
    # Return symmetric range around proportion
    margin_of_error = 1.96 * (proportion * (1 - proportion) / n)**0.5 if n > 0 else 0
    lower_bound = max(0, proportion - margin_of_error)
    upper_bound = min(1, proportion + margin_of_error)
    
    return {
        'lower': lower_bound,
        'upper': upper_bound
    }

def finalize_trace_correlation(trace_id: str) -> bool:
    """
    Finalize a trace correlation (mark as complete).
    
    Args:
        trace_id (str): Unique trace identifier
        
    Returns:
        bool: True if trace was found and finalized
    """
    if trace_id in _trace_correlations:
        _trace_correlations[trace_id]['finalized'] = True
        return True
    return False

def export_correlations(filename: str) -> None:
    """
    Export all correlations to a JSON file.
    
    Args:
        filename (str): Output filename
    """
    with open(filename, 'w') as f:
        json.dump(_trace_correlations, f, indent=2)

def import_correlations(filename: str) -> None:
    """
    Import correlations from a JSON file.
    
    Args:
        filename (str): Input filename
    """
    try:
        with open(filename, 'r') as f:
            global _trace_correlations
            _trace_correlations = json.load(f)
    except FileNotFoundError:
        # File doesn't exist yet, that's okay
        pass