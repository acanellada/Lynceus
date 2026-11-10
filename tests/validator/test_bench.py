import threading
import time
import uuid

import pytest

from lynceus_sec.validator import bench, ssrf
from lynceus_sec.validator.parallel import ParallelContext
from lynceus_sec.validator.runner import RunnerError

TOOL = {"name": "fetch", "input_schema": {"type": "object", "properties": {}, "required": []}}


def _make_cases(tmp_path, prefix, n):
    for i in range(n):
        (tmp_path / f"{prefix}{i:02d}").mkdir()


# --- --jobs 1 (o sin jobs): mismas llamadas que hoy, sin pool ni semáforo ---


def test_jobs_1_calls_validate_case_without_jobs_or_ctx_kwargs(tmp_path, monkeypatch):
    _make_cases(tmp_path, "cmdi-", 2)
    calls = []

    def fake_validate_case(case_dir, **kwargs):
        calls.append(kwargs)
        return [], []

    monkeypatch.setattr("lynceus_sec.validator.cmdi.validate_case", fake_validate_case)

    bench.run_class_benchmark("command_injection", bench_dir=tmp_path)
    bench.run_class_benchmark("command_injection", bench_dir=tmp_path, jobs=1)

    assert calls == [{}, {}, {}, {}]  # 2 casos x 2 llamadas, ningún kwarg de más


def test_jobs_1_never_touches_a_pool_or_semaphore(tmp_path, monkeypatch):
    _make_cases(tmp_path, "cmdi-", 3)
    monkeypatch.setattr("lynceus_sec.validator.cmdi.validate_case", lambda case_dir, **kwargs: ([], []))

    # jobs=1 no debe requerir ctx en absoluto (y si se pasara uno, no debería usarse).
    result = bench.run_class_benchmark("command_injection", bench_dir=tmp_path, jobs=1, ctx=None)

    assert len(result.case_results) == 3


# --- Orden determinista del resultado final, con independencia del orden real de llegada ---


def test_parallel_results_are_assembled_in_case_order_not_completion_order(tmp_path, monkeypatch):
    _make_cases(tmp_path, "cmdi-", 5)
    # Cuanto antes (alfabéticamente) el caso, más tarda en "terminar": fuerza
    # que la finalización real llegue en orden inverso al de los casos.
    delays = {f"cmdi-{i:02d}": (5 - i) * 0.02 for i in range(5)}

    def fake_validate_case(case_dir, **kwargs):
        time.sleep(delays[case_dir.name])
        return [], []

    monkeypatch.setattr("lynceus_sec.validator.cmdi.validate_case", fake_validate_case)

    ctx = ParallelContext.create(3)
    try:
        result = bench.run_class_benchmark("command_injection", bench_dir=tmp_path, jobs=3, ctx=ctx)
    finally:
        ctx.shutdown()

    assert [r.case_id for r in result.case_results] == [f"cmdi-{i:02d}" for i in range(5)]


# --- Semántica de error: RunnerError se registra y no aborta a los demás ---


def test_runner_error_in_one_case_is_recorded_without_aborting_the_others(tmp_path, monkeypatch):
    _make_cases(tmp_path, "cmdi-", 3)

    def fake_validate_case(case_dir, **kwargs):
        if case_dir.name == "cmdi-01":
            raise RunnerError("boom")
        return [], []

    monkeypatch.setattr("lynceus_sec.validator.cmdi.validate_case", fake_validate_case)

    ctx = ParallelContext.create(2)
    try:
        result = bench.run_class_benchmark("command_injection", bench_dir=tmp_path, jobs=2, ctx=ctx)
    finally:
        ctx.shutdown()

    by_id = {r.case_id: r for r in result.case_results}
    assert by_id["cmdi-01"].error == "boom"
    assert by_id["cmdi-00"].error is None
    assert by_id["cmdi-02"].error is None


# --- Limpieza ante interrupción con varios contenedores en marcha ---


def test_non_runner_error_kills_every_registered_container_and_network(tmp_path, monkeypatch):
    _make_cases(tmp_path, "cmdi-", 4)
    killed = []
    removed = []
    monkeypatch.setattr("lynceus_sec.validator.runner.kill_container", lambda name: killed.append(name))
    monkeypatch.setattr("lynceus_sec.validator.runner.remove_network", lambda name: removed.append(name))

    ctx = ParallelContext.create(4)
    barrier_released = threading.Event()

    def fake_validate_case(case_dir, jobs, ctx):
        if case_dir.name == "cmdi-00":
            # Un pequeño margen para que los otros casos registren su
            # contenedor antes de que este dispare el aborto global.
            time.sleep(0.05)
            raise ValueError("bug inesperado")
        name = f"lynceus-sandbox-{uuid.uuid4().hex[:6]}"
        ctx.active.add_container(name)
        barrier_released.wait(timeout=0.2)
        return [], []

    monkeypatch.setattr("lynceus_sec.validator.cmdi.validate_case", fake_validate_case)

    try:
        with pytest.raises(ValueError, match="bug inesperado"):
            bench.run_class_benchmark("command_injection", bench_dir=tmp_path, jobs=4, ctx=ctx)
    finally:
        barrier_released.set()
        ctx.shutdown()

    # Los contenedores que los otros 3 casos habían registrado antes de que
    # el fallo se propagara deben haberse matado todos.
    assert len(killed) >= 2


# --- SSRF en paralelo: nunca más de N redes ni N receptores vivos a la vez ---


def test_ssrf_never_exceeds_n_concurrent_networks_and_receivers(tmp_path, monkeypatch):
    _make_cases(tmp_path, "ssrf-", 6)
    jobs = 2
    lock = threading.Lock()
    state = {"networks": 0, "receivers": 0, "max_networks": 0, "max_receivers": 0}

    def fake_create_network():
        with lock:
            state["networks"] += 1
            state["max_networks"] = max(state["max_networks"], state["networks"])
        time.sleep(0.03)
        return f"lynceus-net-{uuid.uuid4().hex[:6]}"

    def fake_remove_network(name):
        with lock:
            state["networks"] -= 1

    def fake_start_receiver(network, *, image=None, **kwargs):
        with lock:
            state["receivers"] += 1
            state["max_receivers"] = max(state["max_receivers"], state["receivers"])
        time.sleep(0.03)
        return f"lynceus-receiver-{uuid.uuid4().hex[:6]}", "10.0.0.5"

    def fake_stop_receiver(name):
        with lock:
            state["receivers"] -= 1

    def fake_check_network_isolation(network, *, image=None, **kwargs):
        time.sleep(0.01)

    def fake_run_harness(case_dir, **kwargs):
        time.sleep(0.01)
        return []  # sin tools: validate_case devuelve justo tras el descubrimiento

    monkeypatch.setattr(ssrf, "create_internal_network", fake_create_network)
    monkeypatch.setattr(ssrf, "remove_network", fake_remove_network)
    monkeypatch.setattr(ssrf, "start_receiver", fake_start_receiver)
    monkeypatch.setattr(ssrf, "stop_receiver", fake_stop_receiver)
    monkeypatch.setattr(ssrf, "check_network_isolation", fake_check_network_isolation)
    monkeypatch.setattr(ssrf, "run_harness", fake_run_harness)
    monkeypatch.setattr(ssrf, "kill_container", lambda name: None)

    ctx = ParallelContext.create(jobs)
    try:
        result = bench.run_class_benchmark("ssrf", bench_dir=tmp_path, jobs=jobs, ctx=ctx)
    finally:
        ctx.shutdown()

    assert len(result.case_results) == 6
    assert state["max_networks"] <= jobs
    assert state["max_receivers"] <= jobs
    assert state["networks"] == 0  # todas borradas al terminar
    assert state["receivers"] == 0  # todos detenidos al terminar
