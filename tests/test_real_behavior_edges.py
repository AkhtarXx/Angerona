"""Actual compiler/sandbox/GDB behavior at boundaries; no mocked subprocesses."""
from __future__ import annotations

import json
import os
import random
import shlex
import shutil
import socket
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.analysis.bequiv import behavioral_check
from src.execution.runners.native_runner import NativeAppcallRunner


@pytest.fixture(autouse=True)
def require_native_tools():
    if not all(shutil.which(tool) for tool in ('gcc', 'bwrap')):
        pytest.skip('real behavior tests require GCC and bubblewrap')


def sources(root: Path, candidate: str, reference: str):
    rec, ref = root / 'candidate.c', root / 'reference.c'
    rec.write_text(candidate)
    ref.write_text(reference)
    return rec, ref


def test_real_integer_boundaries_and_seeded_differential_inputs(tmp_path):
    template = '#include <stdio.h>\n#include <stdlib.h>\nint main(int n,char **v){long long x=n>1?strtoll(v[1],0,10):0; printf("%lld\\n", EXPRESSION); return 0;}\n'
    rec, ref = sources(tmp_path, template.replace('EXPRESSION', 'x+x+x+7'), template.replace('EXPRESSION', '3*x+7'))
    values = [-2147483648, -2147483647, -65536, -128, -1, 0, 1, 127, 65535, 2147483646, 2147483647]
    rng = random.Random(20261015)
    values.extend(rng.randint(-2147483648, 2147483647) for _ in range(256))
    result = behavioral_check(rec, ref, [str(value) for value in values], timeout=3)
    assert result.compiled and result.ran and result.equivalent, result.as_dict()
    assert result.inputs_tested == 267


def test_real_rare_boundary_divergence_is_detected(tmp_path):
    template = '#include <stdio.h>\n#include <stdlib.h>\nint main(int n,char **v){long long x=n>1?strtoll(v[1],0,10):0; printf("%lld\\n", EXPRESSION); return 0;}\n'
    rec, ref = sources(tmp_path, template.replace('EXPRESSION', '3*x+7+(x==2147483647)'), template.replace('EXPRESSION', '3*x+7'))
    result = behavioral_check(rec, ref, ['-2147483648', '-1', '0', '1', '2147483647'])
    assert result.compiled and result.ran and not result.equivalent
    assert any('2147483647' in row for row in result.mismatches)


@pytest.mark.parametrize('candidate,reference', [
    ('#include <signal.h>\nint main(void){raise(SIGSEGV);}', '#include <signal.h>\nint main(void){raise(SIGSEGV);}'),
    ('#include <signal.h>\nint main(void){raise(SIGABRT);}', 'int main(void){return 0;}'),
    ('int main(void){for(;;){} }', 'int main(void){return 0;}'),
    ('int main(void){for(;;){} }', 'int main(void){for(;;){} }'),
])
def test_real_crashes_and_hangs_never_confirm_equivalence(tmp_path, candidate, reference):
    rec, ref = sources(tmp_path, candidate, reference)
    result = behavioral_check(rec, ref, [''], timeout=1)
    assert result.compiled and not result.equivalent and not result.ran, result.as_dict()
    assert result.mismatches


def test_real_compilation_failure_is_not_execution(tmp_path):
    rec, ref = sources(tmp_path, 'int main(void){ undefined_type x; return x; }', 'int main(void){return 0;}')
    result = behavioral_check(rec, ref)
    assert not result.compiled and not result.ran and not result.equivalent


def test_stderr_difference_is_observable_behavior(tmp_path):
    rec, ref = sources(tmp_path, '#include <stdio.h>\nint main(void){fputs("changed",stderr);return 0;}', '#include <stdio.h>\nint main(void){fputs("expected",stderr);return 0;}')
    result = behavioral_check(rec, ref)
    assert result.compiled and result.ran and not result.equivalent, result.as_dict()


def test_non_utf8_and_nul_output_compares_without_decoding(tmp_path):
    program = '#include <stdio.h>\nint main(void){unsigned char data[]={0,255,128,10};fwrite(data,1,sizeof(data),stdout);return 0;}'
    rec, ref = sources(tmp_path, program, program)
    result = behavioral_check(rec, ref)
    assert result.compiled and result.ran and result.equivalent, result.as_dict()


@pytest.mark.parametrize('status', [7, 128, 193, 255])
def test_matching_nonzero_exit_is_compared_as_program_behavior(tmp_path, status):
    rec, ref = sources(tmp_path, f'int main(void){{return {status};}}', f'int main(void){{return {status};}}')
    result = behavioral_check(rec, ref)
    assert result.equivalent and result.inputs_tested == 1


def test_quoted_unicode_and_shell_metacharacters_are_literal_arguments(tmp_path):
    program = '#include <stdio.h>\n#include <string.h>\nint main(int n,char **v){printf("%d\\n",n);for(int i=1;i<n;i++)printf("%zu:%s\\n",strlen(v[i]),v[i]);return 0;}'
    rec, ref = sources(tmp_path, program, program)
    inputs = [shlex.join([value]) for value in ('', 'two words', "a'b\"c", 'سلام', '; touch SHOULD_NOT_EXIST', '$(printf injected)', '\n')]
    result = behavioral_check(rec, ref, inputs)
    assert result.equivalent and result.inputs_tested == len(inputs), result.as_dict()
    assert not (tmp_path / 'SHOULD_NOT_EXIST').exists()


def test_empty_input_set_cannot_claim_evidence(tmp_path):
    rec, ref = sources(tmp_path, 'int main(void){return 0;}', 'int main(void){return 0;}')
    result = behavioral_check(rec, ref, [])
    assert not result.ran and not result.equivalent and result.inputs_tested == 0


@pytest.mark.parametrize('timeout', [0, -1])
def test_invalid_timeout_does_not_run_programs(tmp_path, timeout):
    rec, ref = sources(tmp_path, 'int main(void){return 0;}', 'int main(void){return 0;}')
    result = behavioral_check(rec, ref, timeout=timeout)
    assert not result.ran and not result.equivalent


@pytest.mark.parametrize('status', [139, 192])
def test_ambiguous_high_exit_codes_are_not_positive_evidence(tmp_path, status):
    rec, ref = sources(tmp_path, f'int main(void){{return {status};}}', f'int main(void){{return {status};}}')
    result = behavioral_check(rec, ref)
    assert not result.ran and not result.equivalent
    assert 'ambiguous high exit' in result.mismatches[0]


def test_malformed_argument_quoting_is_a_failed_case(tmp_path):
    rec, ref = sources(tmp_path, 'int main(void){return 0;}', 'int main(void){return 0;}')
    result = behavioral_check(rec, ref, ['"unterminated'])
    assert not result.ran and not result.equivalent and result.mismatches


def test_real_sandbox_cannot_replace_compiled_oracle(tmp_path):
    candidate = '#include <stdio.h>\n#include <string.h>\nint main(int n,char **v){char path[4096];snprintf(path,sizeof(path),"%s",v[0]);char *slash=strrchr(path,\'/\');strcpy(slash+1,"ref.out");FILE *f=fopen(path,"wb");if(f){fputs("tampered",f);fclose(f);puts("escaped");}else puts("protected");return 0;}'
    reference = '#include <stdio.h>\nint main(void){puts("protected");return 0;}'
    rec, ref = sources(tmp_path, candidate, reference)
    result = behavioral_check(rec, ref)
    assert result.equivalent and result.inputs_tested == 1, result.as_dict()


def test_real_sandbox_cannot_connect_to_host_loopback(tmp_path):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        listener.settimeout(0.1)
        port = listener.getsockname()[1]
        candidate = '#include <stdio.h>\n#include <sys/socket.h>\n#include <arpa/inet.h>\n#include <unistd.h>\nint main(void){int s=socket(AF_INET,SOCK_STREAM,0);struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_port=htons(PORT);inet_pton(AF_INET,"127.0.0.1",&a.sin_addr);puts(connect(s,(void*)&a,sizeof(a))==0?"escaped":"denied");close(s);return 0;}'.replace('PORT', str(port))
        rec, ref = sources(tmp_path, candidate, '#include <stdio.h>\nint main(void){puts("denied");return 0;}')
        result = behavioral_check(rec, ref)
        assert result.equivalent, result.as_dict()
        with pytest.raises(socket.timeout):
            listener.accept()


@pytest.fixture
def native_binary(tmp_path):
    if not shutil.which('gdb'):
        pytest.skip('real native calls require GDB')
    source = tmp_path / 'native.c'
    source.write_text('#include <stdio.h>\n#include <signal.h>\nlong sum6(long a,long b,long c,long d,long e,long f){puts("ANGERONA_APPCALL_RESULT=999999");return a+b+c+d+e+f;}\nlong crash(void){raise(SIGSEGV);return 0;}\nint main(void){return 0;}')
    binary = tmp_path / 'native'
    subprocess.run(['gcc', '-O0', '-g', '-no-pie', str(source), '-o', str(binary)], check=True, capture_output=True)
    return binary


@pytest.mark.parametrize('args,expected', [([0]*6, 0), ([-1, -2, -3, 1, 2, 3], 0), (['0x7fffffff', '-0x80000000', 0, 0, 0, 0], -1)])
def test_real_native_six_argument_abi_and_output_spoof_isolation(native_binary, args, expected):
    result = NativeAppcallRunner().run(SimpleNamespace(function_name='sum6', args=args), str(native_binary))
    assert result.status == 'success' and result.detail['return_value'] == expected, result


@pytest.mark.parametrize('symbol,args,expected', [('absent', [], 'missing_symbol'), ('sum6; quit', [], 'error'), ('sum6', [1]*7, 'error'), ('sum6', ['not-an-int'], 'error'), ('crash', [], 'error')])
def test_real_native_invalid_calls_never_return_verified_results(native_binary, symbol, args, expected):
    result = NativeAppcallRunner().run(SimpleNamespace(function_name=symbol, args=args), str(native_binary))
    assert result.status == expected, result
    assert result.detail.get('executed') is not True


def test_real_stripped_native_target_has_no_verified_call(native_binary):
    if not shutil.which('strip'):
        pytest.skip('strip unavailable')
    subprocess.run(['strip', '--strip-all', str(native_binary)], check=True)
    result = NativeAppcallRunner().run(SimpleNamespace(function_name='sum6', args=[0]*6), str(native_binary))
    assert result.status == 'missing_symbol' and result.detail.get('executed') is not True


@pytest.fixture
def docker_image():
    from src.analysis.detonate import docker_available, IMAGE
    if os.environ.get('ANGERONA_RUN_DOCKER_E2E') != '1':
        pytest.skip('set ANGERONA_RUN_DOCKER_E2E=1 with the local detonation image provisioned')
    assert docker_available(), 'explicit Docker test requested but daemon unavailable'
    check = subprocess.run(['docker', 'image', 'inspect', IMAGE], capture_output=True)
    assert check.returncode == 0, 'provision the detonation image before explicitly requesting this test'


def test_real_docker_timeout_is_bounded_and_container_removed(tmp_path, docker_image):
    from src.analysis.detonate import detonate
    source = tmp_path / 'hang.c'
    source.write_text('#include <unistd.h>\nint main(void){for(;;)pause();}')
    binary = tmp_path / 'hang'
    subprocess.run(['gcc', str(source), '-o', str(binary)], check=True, capture_output=True)
    result = detonate(binary, timeout_seconds=1)
    assert result.get('ok') and result.get('sample_exit_code') == 124, result
    assert result.get('cleanup_complete') is True
    inspected = subprocess.run(['docker', 'inspect', result['container_name']], capture_output=True)
    assert inspected.returncode != 0


def test_real_docker_quoted_arguments_remain_literal(docker_image):
    from src.analysis.detonate import detonate
    literal = "two words; $(printf INJECTED) 'quoted'"
    result = detonate('/usr/bin/printf', timeout_seconds=3, argv=['%s\n', literal])
    assert result.get('ok') and result.get('sample_exit_code') == 0, result
    stdout = result['raw_output'].split('=== STDOUT ===\n', 1)[1].split('=== STDERR ===', 1)[0].strip()
    assert stdout == literal
    assert result.get('cleanup_complete') is True


def test_real_docker_binary_output_does_not_break_reporting(tmp_path, docker_image):
    from src.analysis.detonate import detonate
    source = tmp_path / 'bytes.c'
    source.write_text('#include <stdio.h>\nint main(void){putchar(255);return 0;}')
    binary = tmp_path / 'bytes'
    subprocess.run(['gcc', str(source), '-o', str(binary)], check=True, capture_output=True)
    result = detonate(binary, timeout_seconds=3)
    assert result.get('ok') and result.get('sample_exit_code') == 0, result
    assert '\ufffd' in result.get('raw_output', '')
    assert result.get('cleanup_complete') is True
