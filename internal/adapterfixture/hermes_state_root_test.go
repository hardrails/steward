package adapterfixture

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestHermesStateRootOwnership(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	program := `
import importlib.util, os, pathlib, stat, sys, tempfile
from types import SimpleNamespace
from unittest import mock
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('entrypoint', sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
with tempfile.TemporaryDirectory() as temporary:
    root = pathlib.Path(temporary)
    cases = [(0,65532,0o770,True), (65532,65532,0o755,True),
             (0,65532,0o755,False), (0,65532,0o777,False),
             (0,0,0o770,False), (1000,65532,0o770,False),
             (65532,1000,0o770,False)]
    for uid,gid,mode,accepted in cases:
        info = SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=stat.S_IFDIR|mode)
        with mock.patch.object(module, 'STATE', root), mock.patch.object(module.os, 'fstat', return_value=info):
            try:
                fd = module.open_state_directory()
            except SystemExit:
                assert not accepted, (uid,gid,mode)
            else:
                os.close(fd)
                assert accepted, (uid,gid,mode)
    qualified = SimpleNamespace(st_uid=0, st_gid=65532, st_mode=stat.S_IFDIR|0o770)
    child = SimpleNamespace(st_uid=65532, st_gid=65532, st_mode=stat.S_IFDIR|0o700)
    for child_info, accepted in [(child,True), (qualified,False),
        (SimpleNamespace(st_uid=65532,st_gid=65532,st_mode=stat.S_IFDIR|0o755),False)]:
        with mock.patch.object(module, 'STATE', root), mock.patch.object(module.os, 'fstat', side_effect=[qualified,child_info]):
            try:
                fd = module.open_state_directory('sessions')
            except SystemExit:
                assert not accepted
            else:
                os.close(fd)
                assert accepted
    (root / 'linked').symlink_to(root / 'sessions', target_is_directory=True)
    with mock.patch.object(module, 'STATE', root), mock.patch.object(module.os, 'fstat', return_value=qualified):
        try:
            fd = module.open_state_directory('linked')
        except OSError:
            pass
        else:
            os.close(fd)
            raise AssertionError('state traversal followed a symlink')
`
	command := exec.CommandContext(ctx, python, "-I", "-c", program, filepath.Join(hermesAdapterRoot(t), "entrypoint.py"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("state root regression: %v\n%s", err, output)
	}
}
