# TcpPortDoctor

Utilitário de diagnóstico TCP e MOS Profile 0 para Windows. O executável usa por padrão as portas **10540, 10541 e 10542** e gera um log detalhado na pasta `logs` ao lado do `.exe` (ou na pasta temporária do usuário se não houver permissão de escrita).

O projeto é distribuído sob a licença MIT.

## Uso rápido

Dê dois cliques em `TcpPortDoctor.exe` para abrir o menu interativo.

Para iniciar o servidor de teste, abrir as portas e responder às mensagens MOS Profile 0:

```powershell
.\TcpPortDoctor.exe --listen --bind 0.0.0.0 --seconds 120 --pause
```

O servidor responde a `heartbeat` com `heartbeat`, responde a `reqMachInfo` com `listMachInfo`, aceita `listMachInfo` e descarta `keepAlive` sem resposta, conforme MOS 4.0.

Enquanto o primeiro computador estiver escutando, copie o executável para outro computador e teste a entrada pela rede:

```powershell
.\TcpPortDoctor.exe --connect 192.168.1.50 --ports 10540,10541,10542 --pause
```

Para validar o protocolo, e não somente a conexão TCP:

```powershell
.\TcpPortDoctor.exe --mos-test 192.168.1.50 --ports 10540,10541 --pause
```

Esse teste envia `keepAlive`, envia e valida a resposta de `heartbeat`, envia `reqMachInfo` e valida `listMachInfo` com `mosProfile number="0"`. O XML completo enviado e recebido é gravado no log.

O servidor de teste se identifica no `listMachInfo` como:

```xml
<manufacturer>TCP_DOCTOR</manufacturer>
<model>TcpPortDoctor</model>
```

Troque `192.168.1.50` pelo IP real da máquina que está executando `--listen`.

## O que ele verifica

- sistema, usuário, elevação e versão do .NET;
- interfaces e endereços de rede;
- listeners e conexões existentes nas portas, incluindo PID/processo quando disponível;
- estado dos perfis do Firewall do Windows;
- faixas de portas TCP excluídas/reservadas pelo Windows;
- regras de entrada do Firewall relacionadas às portas;
- `bind` real e listener TCP em cada porta;
- conexão TCP local de autoteste;
- conexões recebidas e XML MOS durante a janela de monitoramento;
- codificação MOS UCS-2/UTF-16 big-endian, com detecção tolerante de UTF-8 e UTF-16 little-endian;
- respostas `heartbeat` e `listMachInfo` do Profile 0;
- DNS, tempo de conexão e códigos detalhados de erro no modo cliente.

## Interpretação básica

- `AddressAlreadyInUse / 10048`: outro processo já ocupa a porta.
- `AddressNotAvailable / 10049`: o IP usado no `bind` não pertence à máquina local.
- `AccessDenied / 10013`: porta reservada/excluída, política de segurança ou software de proteção; compare o teste elevado.
- `ConnectionRefused / 10061`: o host respondeu, mas não há listener na porta (ou houve rejeição ativa).
- `TimedOut / 10060`: geralmente firewall descartando, rota/VLAN/NAT, IP errado ou host desligado.

Um processo **não pode fazer bind no IP de outro computador**. Para abrir a porta de uma máquina específica, execute o programa nessa máquina. A partir de outro computador, use o modo `--connect`.

O utilitário não modifica o Firewall. Se o `bind` e o autoteste local passarem, mas o teste vindo de outro computador falhar, investigue a regra de entrada do Firewall, antivírus/EDR e a topologia da rede.

## Todas as opções

```text
TcpPortDoctor.exe --listen [--bind IP] [--ports LISTA] [--seconds N]
TcpPortDoctor.exe --connect HOST [--ports LISTA] [--timeout MS]
TcpPortDoctor.exe --mos-test HOST [--ports LISTA] [--timeout MS]

--bind IP       IP local; padrão 0.0.0.0
--ports LISTA   padrão 10540,10541,10542
--seconds N     0 mantém os listeners até Ctrl+C; padrão 60
--timeout MS    timeout por conexão; padrão 3000
--mos-id ID     identificador MOS usado nos XMLs
--ncs-id ID     identificador NCS usado nos XMLs
--device-type   tipo anunciado: MOS ou NCS
--pause         aguarda ENTER ao terminar
--no-pause      não aguarda ENTER
--help          exibe ajuda
```

Pelo padrão, Profile 0 trafega nas portas 10540 e 10541. A porta 10542 é destinada à família `mosReqObjList`; o programa permite testá-la para diagnóstico, mas registra essa diferença no log.

## Compatibilidade

Compilado como `AnyCPU` para .NET Framework 4.x, normalmente já presente no Windows 10/11 e Windows Server modernos. O executável não é assinado digitalmente; o Windows pode exibir um aviso de origem desconhecida ao copiá-lo para outra máquina.

## Compilação local

Em uma máquina Windows com o .NET Framework 4.x instalado:

```powershell
.\build.ps1
```

O script localiza o compilador C# do .NET Framework e cria `dist\TcpPortDoctor.exe`.

## GitHub Actions

O workflow `.github/workflows/build.yml` compila o projeto em `windows-latest` a cada push na branch `main`, em pull requests e por acionamento manual. Ao final, o executável fica disponível como artifact chamado `TcpPortDoctor-windows` na execução do GitHub Actions.

## Privacidade dos logs

Os logs podem conter nome da máquina e do usuário, endereços IP, interfaces de rede, processos e configuração do Firewall. Revise o arquivo antes de compartilhá-lo publicamente. A pasta `logs` é ignorada pelo Git para evitar publicação acidental.

## Referências

- [MOS Protocol 4.0](https://mosprotocol.com/wp-content/MOS-Protocol-Documents/MOSProtocolVersion40/index.html)
- [Versões oficiais do MOS Protocol](https://mosprotocol.com/current-version/)
