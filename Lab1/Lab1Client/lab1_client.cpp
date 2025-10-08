#include <iostream>
#include <string>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

// Функции шифрования (из лабораторной работы №3)
unsigned short gamma(char* pwd) {
    char buf[20];
    unsigned long g = 0;
    if (pwd) {
        memset(buf, 0x55, 20);
        memcpy(buf, pwd, strlen(pwd));
        for (int i = 0; i < 20; i++) {
            g += (unsigned long)(buf[i] << (i % 23));
        }
    }
    for (int i = 5; i > 0; i--) {
        unsigned long flag = g & 1;
        g = g >> 1;
        if (flag) g |= 0x80000000;
    }
    return g;
}

int crypt(char* source, char* dest, char* pwd) {
    unsigned short* px = (unsigned short*)source;
    unsigned short* py = (unsigned short*)dest;
    unsigned short g = gamma(pwd);
    int len = strlen(source);
    int numblk = (len + 1) / 4;
    for (int i = 0; i < numblk; i++, py++, px++) {
        *py = *px ^ gamma(0);
    }
    dest[numblk * 4] = '\0';
    return numblk * 4 + 1;
}

int main() {
    std::cout << "=== TCP Client with Encryption ===" << std::endl;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    // Создание сокета
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed." << std::endl;
        WSACleanup();
        return 1;
    }

    // Запрос адреса сервера
    std::string serverIP;
    std::cout << "Enter server IP (127.0.0.1 for localhost): ";
    std::cin >> serverIP;

    // Настройка адреса сервера
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345);
    serverAddr.sin_addr.s_addr = inet_addr(serverIP.c_str());

    // Установка соединения
    std::cout << "Connecting to server..." << std::endl;
    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connection failed." << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Connected to server successfully!" << std::endl;
    std::cout << "Type 'quit' to exit." << std::endl;

    const char* password = "secret123";
    char buffer[1024];
    char encrypted[1024];
    char decrypted[1024];

    std::cin.ignore(); // Очистка буфера

    while (true) {
        // Ввод сообщения
        std::string message;
        std::cout << "Enter message: ";
        std::getline(std::cin, message);

        if (message == "quit") {
            // Шифрование и отправка команды выхода
            crypt(const_cast<char*>(message.c_str()), encrypted, const_cast<char*>(password));
            send(clientSocket, encrypted, strlen(encrypted), 0);
            break;
        }

        // Шифрование сообщения
        crypt(const_cast<char*>(message.c_str()), encrypted, const_cast<char*>(password));

        // Отправка зашифрованного сообщения
        send(clientSocket, encrypted, strlen(encrypted), 0);
        std::cout << "Message sent (encrypted): " << encrypted << std::endl;

        // Прием ответа от сервера
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0) {
            std::cout << "Server disconnected." << std::endl;
            break;
        }

        buffer[bytesReceived] = '\0';

        // Дешифрование ответа
        crypt(buffer, decrypted, const_cast<char*>(password));
        std::cout << "Server response (decrypted): " << decrypted << std::endl;
    }

    // Закрытие соединения
    std::cout << "Closing connection..." << std::endl;
    closesocket(clientSocket);
    WSACleanup();

    std::cout << "Client terminated." << std::endl;
    return 0;
}