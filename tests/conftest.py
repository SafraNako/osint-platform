import re
import pytest

from osint_platformu import fakeworld
from osint_platformu import http as httpmod
from osint_platformu import snapshot as snapmod
from osint_platformu import store as storemod

TARGET = "planted-corp.org"


def make_client(retries=1, timeout=5.0, **kwargs):
    """A client that can only talk to the loopback interface and never sleeps between retries."""
    return httpmod.HttpClient(allow_hosts={"127.0.0.1"}, sleep=lambda s: None, retries=retries, timeout=timeout, **kwargs)


def snapshot_of(store, run_id, target=TARGET):
    meta = next(r for r in store.runs(target) if r["id"] == run_id)
    return snapmod.build_snapshot(store, run_id, target, meta["finished_at"] or meta["started_at"], meta["purpose"])


def run_world(variant="first", faults=None, sources=None, options=None, client=None, store=None, delay=0.3, purpose="validation against a planted organisation"):
    return fakeworld.run_planted(variant, faults=faults, sources=sources, options=options, client=client, store=store or storemod.Store(":memory:"), delay=delay, purpose=purpose)


@pytest.fixture(scope="session")
def first():
    return run_world("first")


@pytest.fixture(scope="session")
def later_in_same_store(first):
    return run_world("later", store=first.store)


def emails_in(text):
    return set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text))
