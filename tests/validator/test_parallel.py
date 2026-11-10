import subprocess

import pytest

from lynceus_sec.validator import parallel
from lynceus_sec.validator.parallel import (
    ActiveSet,
    JobsError,
    ParallelContext,
    docker_cpu_count,
    partition,
    validate_jobs,
)

# --- validate_jobs: límites 1..16 ---


@pytest.mark.parametrize("value", [1, 2, 8, 16])
def test_validate_jobs_accepts_the_documented_range(value):
    assert validate_jobs(value) == value


@pytest.mark.parametrize("value", [0, -1, 17, 100])
def test_validate_jobs_rejects_outside_the_documented_range(value):
    with pytest.raises(JobsError, match="--jobs"):
        validate_jobs(value)


# --- docker_cpu_count: parsea `docker info --format '{{.NCPU}}'` ---


def test_docker_cpu_count_parses_integer_output(monkeypatch):
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="8\n", stderr="")
    monkeypatch.setattr(parallel.subprocess, "run", lambda *a, **k: completed)

    assert docker_cpu_count() == 8


def test_docker_cpu_count_none_when_docker_info_fails(monkeypatch):
    completed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="boom")
    monkeypatch.setattr(parallel.subprocess, "run", lambda *a, **k: completed)

    assert docker_cpu_count() is None


def test_docker_cpu_count_none_on_unparseable_output(monkeypatch):
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="not-a-number\n", stderr="")
    monkeypatch.setattr(parallel.subprocess, "run", lambda *a, **k: completed)

    assert docker_cpu_count() is None


def test_docker_cpu_count_none_on_timeout(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout", 0))

    monkeypatch.setattr(parallel.subprocess, "run", fake_run)

    assert docker_cpu_count() is None


def test_docker_cpu_count_none_when_binary_is_missing(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(parallel.subprocess, "run", fake_run)

    assert docker_cpu_count() is None


# --- partition: reparto determinista en como mucho N trozos, sin reordenar ---


def test_partition_empty_list_returns_no_chunks():
    assert partition([], 4) == []


def test_partition_with_one_job_returns_a_single_chunk():
    assert partition([1, 2, 3], 1) == [[1, 2, 3]]


def test_partition_never_creates_more_chunks_than_items():
    assert partition([1, 2], 8) == [[1], [2]]


def test_partition_preserves_order_within_and_across_chunks():
    items = list(range(10))
    chunks = partition(items, 3)

    assert sum(len(c) for c in chunks) == len(items)
    assert [x for chunk in chunks for x in chunk] == items


def test_partition_is_deterministic_for_the_same_inputs():
    items = list(range(17))

    assert partition(items, 5) == partition(items, 5)


def test_partition_balances_chunk_sizes_within_one():
    items = list(range(10))
    chunks = partition(items, 3)

    sizes = sorted(len(c) for c in chunks)
    assert sizes == [3, 3, 4]


# --- ActiveSet: limpieza de todo lo registrado, independientemente del orden ---


def test_kill_and_clear_kills_every_registered_container_and_network(monkeypatch):
    from lynceus_sec.validator import runner

    killed = []
    removed = []
    monkeypatch.setattr(runner, "kill_container", lambda name: killed.append(name))
    monkeypatch.setattr(runner, "remove_network", lambda name: removed.append(name))

    active = ActiveSet()
    for name in ("c1", "c2", "c3"):
        active.add_container(name)
    for name in ("net1", "net2"):
        active.add_network(name)

    active.kill_and_clear()

    assert sorted(killed) == ["c1", "c2", "c3"]
    assert sorted(removed) == ["net1", "net2"]


def test_discarded_names_are_not_killed_again(monkeypatch):
    from lynceus_sec.validator import runner

    killed = []
    monkeypatch.setattr(runner, "kill_container", lambda name: killed.append(name))
    monkeypatch.setattr(runner, "remove_network", lambda name: None)

    active = ActiveSet()
    active.add_container("c1")
    active.add_container("c2")
    active.discard_container("c1")

    active.kill_and_clear()

    assert killed == ["c2"]


def test_kill_and_clear_empties_the_registry():
    active = ActiveSet()
    active.add_container("c1")
    active.add_network("net1")

    active.kill_and_clear()

    assert active._containers == set()
    assert active._networks == set()


# --- ParallelContext: pool y semáforo del mismo tamaño ---


def test_parallel_context_create_sizes_pool_and_semaphore_to_jobs():
    ctx = ParallelContext.create(3)
    try:
        assert ctx.pool._max_workers == 3
        acquired = [ctx.semaphore.acquire(blocking=False) for _ in range(4)]
        assert acquired == [True, True, True, False]
    finally:
        for ok in acquired:
            if ok:
                ctx.semaphore.release()
        ctx.shutdown()
