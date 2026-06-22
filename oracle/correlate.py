"""
Trace ID correlation for Oracle module.
Correlates trace IDs from API requests with Oracle detections for ASR calculation.
"""

import uuid
from typing import Dict, List, Any, Optional
import math
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
        'confidence_interval': calculate_wilson_score_confidence_interval(asr, total_tests)
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

def calculate_wilson_score_confidence_interval(proportion: float, n: int, confidence: float = 0.95) -> Dict[str, float]:
    """
    Calculate Wilson score interval for proportion confidence.
    
    Using the Wilson score interval formula for better accuracy,
    especially with small sample sizes.
    
    Args:
        proportion (float): Observed proportion (ASR value)
        n (int): Sample size
        confidence (float): Confidence level (default 0.95 for 95%)
        
    Returns:
        Dict[str, float]: Lower and upper bounds of confidence interval
    """
    if n == 0:
        return {'lower': 0.0, 'upper': 0.0}
    
    # Z-score for confidence level
    if confidence == 0.90:
        z = 1.645
    elif confidence == 0.95:
        z = 1.96
    elif confidence == 0.99:
        z = 2.576
    else:
        z = 1.96  # default to 95% confidence
    
    # Wilson score interval calculation
    phat = proportion
    denominator = 1 + z**2 / n
    center = (phat + z**2 / (2 * n)) / denominator
    radius = z * math.sqrt(phat * (1 - phat) / n + z**2 / (4 * n**2)) / denominator
    lower_bound = max(0, center - radius)
    upper_bound = min(1, center + radius)
    
    return {
        'lower': lower_bound,
        'upper': upper_bound
    }

def calculate_binomial_confidence_interval(proportion: float, n: int, confidence: float = 0.95) -> Dict[str, float]:
    """
    Calculate binomial confidence interval using normal approximation.
    
    Args:
        proportion (float): Observed proportion
        n (int): Sample size
        confidence (float): Confidence level
        
    Returns:
        Dict[str, float]: Lower and upper bounds of confidence interval
    """
    if n == 0:
        return {'lower': 0.0, 'upper': 0.0}
    
    # Z-score for confidence level
    if confidence == 0.90:
        z = 1.645
    elif confidence == 0.95:
        z = 1.96
    elif confidence == 0.99:
        z = 2.576
    else:
        z = 1.96  # default to 95% confidence
    
    # Standard error
    se = math.sqrt(proportion * (1 - proportion) / n)
    
    # Margin of error
    margin = z * se
    
    lower_bound = max(0, proportion - margin)
    upper_bound = min(1, proportion + margin)
    
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

def calculate_aggregated_asr_stats(target_configs: List[str], success_criteria: str) -> Dict[str, Any]:
    """
    Calculate aggregated ASR statistics across multiple configurations.
    
    Args:
        target_configs (List[str]): List of target configurations
        success_criteria (str): Success criteria for measurements
        
    Returns:
        Dict[str, Any]: Aggregated statistics
    """
    results = {}
    
    for config in target_configs:
        config_results = calculate_asr_from_correlations(config, success_criteria)
        results[config] = config_results
    
    return results

def get_confidence_interval_bounds(asr: float, sample_size: int, confidence: float = 0.95) -> tuple:
    """
    Get confidence interval bounds for ASR values.
    
    Args:
        asr (float): Attack success rate
        sample_size (int): Number of samples
        confidence (float): Confidence level
        
    Returns:
        tuple: (lower_bound, upper_bound) of confidence interval
    """
    ci = calculate_wilson_score_confidence_interval(asr, sample_size, confidence)
    return (ci['lower'], ci['upper'])