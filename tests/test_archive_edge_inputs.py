"""Crafted on-disk ZIP inputs exercise parser/extraction guards without mocks."""
import io
import stat
import struct
import zipfile

import pytest

from src.analysis.archive_router import route
from src.updater import _safe_extract


@pytest.mark.parametrize('member', ['../outside.txt', '/absolute.txt'])
def test_actual_zip_unsafe_paths_rejected_before_extraction(tmp_path, member):
    archive = tmp_path / 'unsafe.zip'
    with zipfile.ZipFile(archive, 'w') as writer:
        writer.writestr(member, 'untrusted')
    destination = tmp_path / 'out'
    with pytest.raises(RuntimeError, match='unsafe zip member'):
        _safe_extract(archive, destination)
    assert not (tmp_path / 'outside.txt').exists()
    assert not destination.exists()


def test_actual_zip_symlink_rejected(tmp_path):
    archive = tmp_path / 'symlink.zip'
    info = zipfile.ZipInfo('link')
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, 'w') as writer:
        writer.writestr(info, '../outside')
    with pytest.raises(RuntimeError, match='symlinks'):
        _safe_extract(archive, tmp_path / 'out')


def test_actual_truncated_zip_never_extracts_successfully(tmp_path):
    archive = tmp_path / 'truncated.zip'
    with zipfile.ZipFile(archive, 'w') as writer:
        writer.writestr('file.txt', 'content')
    archive.write_bytes(archive.read_bytes()[:-12])
    with pytest.raises((zipfile.BadZipFile, RuntimeError)):
        _safe_extract(archive, tmp_path / 'out')


def test_oversized_declared_zip_member_is_not_inflated(tmp_path):
    archive = tmp_path / 'oversize.zip'
    with zipfile.ZipFile(archive, 'w') as writer:
        writer.writestr('payload', b'x')
    payload = bytearray(archive.read_bytes())
    central = payload.index(b'PK\x01\x02')
    declared = 256 * 1024 * 1024 + 1
    struct.pack_into('<I', payload, central + 24, declared)
    struct.pack_into('<I', payload, 22, declared)
    archive.write_bytes(payload)
    result = route(archive)
    assert result.children == [] and result.bytes_extracted == 0
    assert any('exceeds' in row for row in result.unresolved)


def test_actual_nested_zip_stops_at_depth_budget(tmp_path):
    payload = b'leaf'
    for depth in range(11):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as writer:
            writer.writestr(f'level-{depth}.zip', payload)
        payload = buffer.getvalue()
    archive = tmp_path / 'nested.zip'
    archive.write_bytes(payload)
    result = route(archive)
    assert result.truncated
    assert any('depth cap' in row for row in result.unresolved)
