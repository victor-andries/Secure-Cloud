import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())

import numpy as np
from unittest.mock import patch, MagicMock
from ai_detection import detector, redis_buffer
from ai_detection.config import MIN_FIT_SAMPLES, N_FEATURES

def test_load_models_preseeds_when_buffer_empty():
    """load_models() must seed the Redis buffer when it has fewer than MIN_FIT_SAMPLES entries."""
    mock_redis = MagicMock()
    mock_redis.llen.return_value = 0          # buffer is empty
    mock_redis.lrange.return_value = []

    with patch.object(redis_buffer, 'redis_client', mock_redis):
        with patch.object(detector, '_fit_detector') as mock_fit:
            detector.load_models()
            # _fit_detector must have been called with a matrix of shape (MIN_FIT_SAMPLES, N_FEATURES)
            assert mock_fit.called, "Expected _fit_detector to be called after pre-seeding"
            X = mock_fit.call_args[0][0]
            assert X.shape == (MIN_FIT_SAMPLES, N_FEATURES), (
                f"Expected shape ({MIN_FIT_SAMPLES}, {N_FEATURES}), got {X.shape}"
            )

def test_preseed_vectors_are_in_normal_range():
    """Synthetic vectors must look like normal activity (no extreme values)."""
    from ai_detection.detector import _generate_normal_vectors
    X = _generate_normal_vectors(100)
    assert X.shape == (100, N_FEATURES)
    # hour_of_day (index 0) should be in valid range
    assert X[:, 0].min() >= 0
    assert X[:, 0].max() <= 23
    # All values should be non-negative
    assert X.min() >= 0

def test_load_models_preseeds_when_redis_unavailable():
    """load_models() must pre-seed even when Redis is unavailable."""
    with patch.object(redis_buffer, 'redis_client', None):
        with patch.object(detector, '_fit_detector') as mock_fit:
            detector.load_models()
            assert mock_fit.called, "Expected _fit_detector to be called when Redis is unavailable"
            X = mock_fit.call_args[0][0]
            assert X.shape == (MIN_FIT_SAMPLES, N_FEATURES)
