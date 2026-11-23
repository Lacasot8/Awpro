package com.dtunnel.bhttptest;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Abre cada conexão HCR com um handshake HTTP marcado (GET /hcr + Upgrade).
 * Proxies transparentes de operadoras nas portas 80/8080 derrubam tráfego
 * binário; o AWpro (opção H) reconhece este pedido, responde 101 e repassa os
 * frames HCR intactos ao hcr-server. A porta 8880 (hcr-server direto) não usa
 * o handshake, porque o hcr-server não entende HTTP.
 */
public final class HcrHttpUpgrade {
    private static final int DIRECT_HCR_PORT = 8880;
    private static final int MAX_RESPONSE = 8192;
    private static final int HANDSHAKE_TIMEOUT_MS = 10000;
    // RFC 6455 accept para a chave fixa dGhlIHNhbXBsZSBub25jZQ==.
    private static final String EXPECTED_ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    private HcrHttpUpgrade() {}

    public static boolean isEnabledFor(int port) {
        return port != DIRECT_HCR_PORT;
    }

    public static void perform(Socket socket, String host, int port) throws IOException {
        if (!isEnabledFor(port)) {
            return;
        }
        String hostHeader = port == 80 ? host : host + ":" + port;
        String request = "GET /hcr HTTP/1.1\r\n"
                + "Host: " + hostHeader + "\r\n"
                + "Upgrade: websocket\r\n"
                + "Connection: Upgrade\r\n"
                + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                + "Sec-WebSocket-Version: 13\r\n"
                + "X-AzPro-HCR: 1\r\n"
                + "\r\n";
        OutputStream out = socket.getOutputStream();
        out.write(request.getBytes(StandardCharsets.ISO_8859_1));
        out.flush();

        int previousTimeout = socket.getSoTimeout();
        socket.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
        try {
            InputStream in = socket.getInputStream();
            byte[] buffer = new byte[MAX_RESPONSE];
            int length = 0;
            // Lê byte a byte para não consumir nenhum byte HCR depois do cabeçalho.
            while (true) {
                int value = in.read();
                if (value < 0) {
                    throw new IOException("HCR upgrade: conexão fechada pelo servidor");
                }
                if (length >= MAX_RESPONSE) {
                    throw new IOException("HCR upgrade: resposta HTTP muito grande");
                }
                buffer[length++] = (byte) value;
                if (length >= 4 && buffer[length - 4] == '\r' && buffer[length - 3] == '\n'
                        && buffer[length - 2] == '\r' && buffer[length - 1] == '\n') {
                    break;
                }
            }
            String response = new String(buffer, 0, length, StandardCharsets.ISO_8859_1);
            int lineEnd = response.indexOf("\r\n");
            String statusLine = lineEnd >= 0 ? response.substring(0, lineEnd) : response;
            String[] parts = statusLine.split(" ");
            if (parts.length < 2 || !parts[0].startsWith("HTTP/") || !"101".equals(parts[1])) {
                throw new IOException("HCR upgrade recusado: " + statusLine
                        + " (ative a opção H no AWpro nesta porta)");
            }
            if (!response.toLowerCase(java.util.Locale.ROOT).contains(
                    "sec-websocket-accept: " + EXPECTED_ACCEPT.toLowerCase(java.util.Locale.ROOT))) {
                throw new IOException("HCR upgrade: a porta respondeu 101 sem suporte HCR"
                        + " (ative a opção H / Suporte ao HCR no AWpro nesta porta)");
            }
        } finally {
            socket.setSoTimeout(previousTimeout);
        }
    }
}
