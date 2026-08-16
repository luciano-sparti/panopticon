"""Unit tests for the /proc flow -> pid resolver (no real sockets)."""

from panopticon.core import procs


def _make_proc_tree(tmp_path, tables, pid_inodes):
    """Build a fake /proc layout: net tables plus per-pid socket fds."""
    proc = tmp_path / "proc"
    (proc / "net").mkdir(parents=True)
    for name, content in tables.items():
        (proc / "net" / name).write_text(content, encoding="utf-8")
    for pid, fds in pid_inodes.items():
        fd_dir = proc / str(pid) / "fd"
        fd_dir.mkdir(parents=True)
        for fd, inode in fds.items():
            (fd_dir / str(fd)).symlink_to(f"socket:[{inode}]")
    return str(proc)


def test_inet_table_parses_listening_and_connected_inodes():
    text = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
       0: 0100007F:0035 00000000:0000 0A 00000000:00000000 000:00 0 0 0 0 0 258
       1: 0A000001:1F90 9D7B0408:0050 01 00000000:00000000 000:00 0 0 0 0 0 259
       2: 0100007F:1F91 00000000:0000 0A 00000000:00000000 000:00 0 0 0 0 0 260
"""
    candidates = {"258", "259", "260"}
    assert procs._inet_table_inodes(text, 53, candidates) == {"258"}
    assert procs._inet_table_inodes(text, 8080, candidates) == {"259"}
    assert procs._inet_table_inodes(text, 8081, candidates) == {"260"}
    assert procs._inet_table_inodes(text, 9999, candidates) == set()


def test_inet_table_ignores_unrelated_numeric_fields():
    # uid/timeout/etc must not be mistaken for the inode just because they
    # are decimal numbers.
    text = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
       0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 000:00 0 0 0 1000 0 777
"""
    assert procs._inet_table_inodes(text, 8080, {"258", "259"}) == set()
    assert procs._inet_table_inodes(text, 8080, {"258", "259", "777"}) == {"777"}


def test_inet_table_ignores_header_and_empty():
    assert procs._inet_table_inodes("", 53, set()) == set()
    assert procs._inet_table_inodes(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
        53,
        {"258"},
    ) == set()


def test_pids_resolved_from_fake_proc_tree(tmp_path):
    tables = {
        "tcp": """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
       0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 000:00 0 0 0 0 0 4242
       1: 0A000001:0016 00000000:0000 0A 00000000:00000000 000:00 0 0 0 0 0 9999
"""
    }
    pid_inodes = {101: {3: 4242}, 202: {7: 9999}, 303: {2: 5555}}
    proc = _make_proc_tree(tmp_path, tables, pid_inodes)
    assert procs.local_pids_for_port(8080, proc_root=proc) == [101]
    assert procs.local_pids_for_port(22, proc_root=proc) == [202]
    assert procs.local_pids_for_port(8081, proc_root=proc) == []


def test_pids_aggregate_across_tcp_udp_and_multi_fd(tmp_path):
    tables = {
        "tcp": """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
       0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 000:00 0 0 0 0 0 1111
""",
        "udp": """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
       0: 0100007F:1F90 00000000:0000 07 00000000:00000000 000:00 0 0 0 0 0 2222
""",
    }
    pid_inodes = {55: {3: 1111, 4: 2222}, 66: {9: 1111}}
    proc = _make_proc_tree(tmp_path, tables, pid_inodes)
    assert procs.local_pids_for_port(8080, proc_root=proc) == [55, 66]


def test_missing_proc_root_returns_empty(tmp_path):
    assert procs.local_pids_for_port(8080, proc_root=str(tmp_path / "nope")) == []
