# Patch HCR 80/8080 para o AZPro Lite

O `HcrSocketRelay` do APK abre um socket TCP cru, protegido da VPN, para cada
conexão HCR da engine nativa. Nas portas 80/8080 o proxy transparente da
operadora derruba esse tráfego binário. O patch chama
`HcrHttpUpgrade.perform(socket, remoteHost, remotePort)` logo depois do
`Socket.connect(...)` em `HcrSocketRelay.relay`. O helper envia
`GET /hcr` + `Upgrade: websocket`, exige `101` com o `Sec-WebSocket-Accept`
esperado (enviado só pelo AWpro com a opção H ativa) e então libera o relay.
Na porta 8880 (hcr-server direto) nada muda.

Smali inserido em `smali_classes6/com/dtunnel/bhttptest/HcrSocketRelay.smali`,
logo após `invoke-virtual {v1, v2, v3}, Ljava/net/Socket;->connect(Ljava/net/SocketAddress;I)V`:

```smali
    iget-object v2, p0, Lcom/dtunnel/bhttptest/HcrSocketRelay;->remoteHost:Ljava/lang/String;
    iget v3, p0, Lcom/dtunnel/bhttptest/HcrSocketRelay;->remotePort:I
    invoke-static {v1, v2, v3}, Lcom/dtunnel/bhttptest/HcrHttpUpgrade;->perform(Ljava/net/Socket;Ljava/lang/String;I)V
```

Build: `javac --release 8` → `d8 --min-api 25` → smali da classe copiado para
`smali_classes6/com/dtunnel/bhttptest/` → `apktool b` → zipalign + assinatura.
