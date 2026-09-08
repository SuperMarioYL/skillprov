"""Sign and verify temporary copies; never execute fixture scripts."""
from pathlib import Path
from tempfile import TemporaryDirectory
import json, re, shutil, subprocess
binary=Path('bin/skillprov').resolve()
with TemporaryDirectory(prefix='skillprov-demo-') as folder:
    root=Path(folder)
    for name in ['clean-skill','poisoned-skill']:
        shutil.copytree(Path('testdata')/name,root/name)
        subprocess.run([str(binary),'manifest',name],cwd=root,check=True,capture_output=True,text=True)
        subprocess.run([str(binary),'sign',name,'--key','demo.key'],cwd=root,check=True,capture_output=True,text=True)
        result=subprocess.run([str(binary),'verify',name,'--no-color'],cwd=root,capture_output=True,text=True)
        expected=0 if name=='clean-skill' else 1
        assert result.returncode==expected,(name,result.stdout,result.stderr)
        print(re.sub(r'\x1b\[[0-9;]*m','',result.stdout).strip())
        print('exit_code:',result.returncode)
