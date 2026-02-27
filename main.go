package main

import (
	"fmt"
	"net"
)

// DefaultInterface retorna o nome da interface de rede padrão.
func DefaultInterface() (string, error) {
    // Conecta a um servidor externo (não precisa enviar dados)
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        return "", fmt.Errorf("falha ao determinar interface padrão: %w", err)
    }
    defer conn.Close()

    // Obtém o endereço local da conexão
    localAddr := conn.LocalAddr().(*net.UDPAddr)

    // Percorre as interfaces procurando aquela que possui esse IP
    interfaces, err := net.Interfaces()
    if err != nil {
        return "", err
    }

    for _, iface := range interfaces {
        // Verifica se a interface está ativa
        if iface.Flags&net.FlagUp == 0 {
            continue
        }

        addrs, err := iface.Addrs()
        if err != nil {
            continue
        }

        for _, addr := range addrs {
            ipNet, ok := addr.(*net.IPNet)
            if !ok {
                continue
            }
            if ipNet.IP.Equal(localAddr.IP) {
                return iface.Name, nil
            }
        }
    }

    return "", fmt.Errorf("nenhuma interface encontrada com o IP %s", localAddr.IP)
}

func main() {
    ifaceName, err := DefaultInterface()
    if err != nil {
        fmt.Println("Erro:", err)
        return
    }
    fmt.Printf("Interface padrão: %s\n", ifaceName)
}

