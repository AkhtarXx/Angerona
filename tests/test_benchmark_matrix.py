from pathlib import Path

from src.analysis.benchmark_matrix import CorpusMatrix, MatrixEvaluator


def test_corpus_manifest_covers_multiple_compilers_and_reverse_engineering_features() -> None:
    root = Path(__file__).parents[1]
    matrix = CorpusMatrix.load(root / "benchmarks" / "corpus_matrix" / "manifest.json")
    dimensions = matrix.dimensions()
    assert set(dimensions["compilers"]) == {"clang", "g++", "gcc"}
    assert {"cfg", "stripped", "rtti", "vtable"} <= set(dimensions["tags"])


def test_matrix_metrics_and_regression_gates() -> None:
    root = Path(__file__).parents[1]
    matrix = CorpusMatrix.load(root / "benchmarks" / "corpus_matrix" / "manifest.json")
    case = matrix.cases[0]
    metrics = MatrixEvaluator().evaluate_case(case, {
        "functions": ["main", "dispatch", "add_one", "sub_one", "extra"],
        "symbols": ["main", "dispatch"],
        "cfg_edges": [],
    }, 1.5)
    assert metrics.function_recall == 1.0
    assert metrics.function_precision == 0.8
    aggregate = MatrixEvaluator.aggregate([metrics])
    assert MatrixEvaluator.enforce(aggregate, {"function_recall": 0.9, "crashes": 0}) == []
    assert MatrixEvaluator.enforce(aggregate, {"function_precision": 0.9})
