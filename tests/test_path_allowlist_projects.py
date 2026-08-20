"""Path-allowlist coverage for Arkana's own project storage.

``open_file()`` adopts every binary into the active project's ``binaries/``
directory and rewrites ``state.filepath`` to that copy, so any tool that
re-reads its loaded file via ``_get_filepath`` validates the *in-project*
path. Users pass ``--allowed-paths`` pointing at their samples directory,
not at ``~/.arkana``, so before this was handled those tools failed with
"Access denied" in HTTP mode (where ``--allowed-paths`` is mandatory).

These tests pin both halves: the project's own storage is reachable, and
widening it did not turn the allowlist into a way to read anything else.
"""
import os
from pathlib import Path

import pytest

from arkana.state import AnalyzerState


class _Project:
    """Stand-in for a real on-disk Project."""

    def __init__(self, root: Path):
        self.root = root
        self.binaries_dir = root / "binaries"
        self.artifacts_dir = root / "artifacts"
        self.binaries_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)


class _Scratch:
    """Stand-in for ScratchProject — in-memory, no disk presence."""


@pytest.fixture
def st(tmp_path):
    s = AnalyzerState()
    samples = tmp_path / "samples"
    samples.mkdir()
    s.allowed_paths = [str(samples)]
    return s


@pytest.fixture
def samples(tmp_path):
    return tmp_path / "samples"


class TestBaselineBehaviourUnchanged:
    def test_no_restriction_configured_allows_everything(self):
        s = AnalyzerState()
        s.allowed_paths = None
        s.check_path_allowed("/etc/passwd")  # must not raise

    def test_path_inside_allowlist_is_permitted(self, st, samples):
        st.check_path_allowed(str(samples / "sample.exe"))

    def test_path_outside_allowlist_is_denied(self, st):
        with pytest.raises(RuntimeError, match="Access denied"):
            st.check_path_allowed("/etc/passwd")

    def test_denial_does_not_disclose_the_path(self, st):
        with pytest.raises(RuntimeError) as exc:
            st.check_path_allowed("/etc/shadow")
        assert "/etc/shadow" not in str(exc.value)


class TestActiveProjectStorage:
    def test_binaries_dir_is_reachable(self, st, tmp_path):
        proj = _Project(tmp_path / "proj-a")
        st.bind_project(proj)
        st.check_path_allowed(str(proj.binaries_dir / "abcd_sample.exe"))

    def test_artifacts_dir_is_reachable(self, st, tmp_path):
        proj = _Project(tmp_path / "proj-a")
        st.bind_project(proj)
        st.check_path_allowed(str(proj.artifacts_dir / "unpacked.bin"))

    def test_project_root_itself_is_not_blanket_allowed(self, st, tmp_path):
        """overlay/ and manifest.json hold user notes, not sample data."""
        proj = _Project(tmp_path / "proj-a")
        st.bind_project(proj)
        with pytest.raises(RuntimeError, match="Access denied"):
            st.check_path_allowed(str(proj.root / "manifest.json"))

    def test_other_projects_are_not_reachable(self, st, tmp_path):
        """The allowlist is per-session; it must not become a shared channel.

        Binding project A must not let this session read a binary that
        another session adopted into project B by guessing the path.
        """
        a = _Project(tmp_path / "proj-a")
        b = _Project(tmp_path / "proj-b")
        st.bind_project(a)
        with pytest.raises(RuntimeError, match="Access denied"):
            st.check_path_allowed(str(b.binaries_dir / "secret.exe"))

    def test_unbinding_revokes_access(self, st, tmp_path):
        proj = _Project(tmp_path / "proj-a")
        st.bind_project(proj)
        st.check_path_allowed(str(proj.binaries_dir / "x.exe"))
        st.unbind_project()
        with pytest.raises(RuntimeError, match="Access denied"):
            st.check_path_allowed(str(proj.binaries_dir / "x.exe"))

    def test_scratch_project_grants_nothing(self, st):
        """ScratchProject has no binaries_dir/artifacts_dir attributes."""
        st.bind_project(_Scratch())
        with pytest.raises(RuntimeError, match="Access denied"):
            st.check_path_allowed("/etc/passwd")

    def test_no_project_bound_grants_nothing(self, st):
        assert st.get_active_project() is None
        with pytest.raises(RuntimeError, match="Access denied"):
            st.check_path_allowed("/etc/passwd")

    def test_project_with_unusable_dir_attrs_does_not_crash(self, st):
        class Weird:
            binaries_dir = None
            artifacts_dir = "\x00not-a-path"

        st.bind_project(Weird())
        with pytest.raises(RuntimeError, match="Access denied"):
            st.check_path_allowed("/etc/passwd")


class TestSymlinkEscape:
    def test_symlink_out_of_binaries_dir_is_denied(self, st, tmp_path):
        """A symlink planted in binaries/ must not tunnel out.

        Validation resolves the candidate with realpath before comparing, so
        the link's *target* is what gets checked.
        """
        proj = _Project(tmp_path / "proj-a")
        secret = tmp_path / "outside" / "secret.txt"
        secret.parent.mkdir(parents=True, exist_ok=True)
        secret.write_text("sensitive")
        link = proj.binaries_dir / "innocent.exe"
        try:
            os.symlink(secret, link)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable on this platform")
        st.bind_project(proj)
        with pytest.raises(RuntimeError, match="Access denied"):
            st.check_path_allowed(str(link))

    def test_symlink_within_binaries_dir_is_permitted(self, st, tmp_path):
        proj = _Project(tmp_path / "proj-a")
        real = proj.binaries_dir / "real.exe"
        real.write_bytes(b"MZ")
        link = proj.binaries_dir / "alias.exe"
        try:
            os.symlink(real, link)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable on this platform")
        st.bind_project(proj)
        st.check_path_allowed(str(link))
