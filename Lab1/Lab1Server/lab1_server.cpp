#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

// Функция генерации гаммы
unsigned int gamma(const char* pwd) {
    char buf[20];
    unsigned int g = 0;
    if (pwd) {
        memset(buf, 0x55, 20);
        strncpy_s(buf, pwd, 19);
        for (int i = 0; i < 20; i++) {
            g += (unsigned int)(buf[i] << (i % 16));
        }
    }
    for (int i = 5; i > 0; i--) {
        unsigned int flag = g & 1;
        g = g >> 1;
        if (flag) g |= 0x80000000;
    }
    return g;
}

// Функция шифрования/дешифрования
void crypt(const std::string& source, std::string& dest, const char* pwd) {
    dest.clear();
    unsigned int g = gamma(pwd);

    for (size_t i = 0; i < source.length(); i++) {
        // XOR-шифрование каждого символа
        char encrypted_char = source[i] ^ (char)(g & 0xFF);
        dest += encrypted_char;

        // Циклический сдвиг гаммы
        g = (g >> 1) | (g << 31);
    }
}

// Функция для обработки клиента
void handleClient(SOCKET clientSocket, sockaddr_in clientAddr) {
    char clientIP[16];
    strcpy_s(clientIP, inet_ntoa(clientAddr.sin_addr));
    std::cout << "Client connected: " << clientIP << ":" << ntohs(clientAddr.sin_port) << std::endl;

    char buffer[1024];
    const char* password = "secret123";

    while (true) {
        // Прием данных от клиента
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0) {
            std::cout << "Client disconnected: " << clientIP << std::endl;
            break;
        }

        buffer[bytesReceived] = '\0';

        std::string received_msg(buffer, bytesReceived);
        std::string decrypted_msg;

        // Дешифрование данных
        crypt(received_msg, decrypted_msg, password);

        std::cout << "Received encrypted (" << bytesReceived << " bytes)" << std::endl;
        std::cout << "Decrypted message: " << decrypted_msg << std::endl;

        // Обработка команды выхода
        if (decrypted_msg == "quit") {
            std::cout << "Client requested disconnect: " << clientIP << std::endl;
            break;
        }

        // Подготовка ответа
        std::string response = "Server received: " + decrypted_msg;
        std::string encrypted_response;

        // Шифрование ответа
        crypt(response, encrypted_response, password);

        // Отправка ответа клиенту
        send(clientSocket, encrypted_response.c_str(), encrypted_response.length(), 0);
        std::cout << "Response sent to client" << std::endl;
    }

    closesocket(clientSocket);
}

int main() {
    std::cout << "=== TCP Server with Encryption ===" << std::endl;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    // Создание сокета
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed." << std::endl;
        WSACleanup();
        return 1;
    }

    // Настройка адреса сервера
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    // Привязка сокета
    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed." << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    // Прослушивание порта
    if (listen(serverSocket, 10) == SOCKET_ERROR) {
        std::cerr << "Listen failed." << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server is listening on port 12345..." << std::endl;
    std::cout << "Waiting for connections..." << std::endl;

    while (true) {
        // Принятие соединения
        sockaddr_in clientAddr;
        int clientSize = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientSize);

        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed." << std::endl;
            continue;
        }

        // Обработка клиента
        handleClient(clientSocket, clientAddr);
    }

    // Закрытие серверного сокета
    closesocket(serverSocket);
    WSACleanup();

    return 0;
}