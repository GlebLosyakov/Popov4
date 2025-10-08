#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

// ������� ���������� (�� ������������ ������ �3)
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

// ������� ��� ��������� �������
void handleClient(SOCKET clientSocket, sockaddr_in clientAddr) {
    char clientIP[16]; // IPv4 �����
    strcpy_s(clientIP, inet_ntoa(clientAddr.sin_addr));
    std::cout << "Client connected: " << clientIP << ":" << ntohs(clientAddr.sin_port) << std::endl;

    char buffer[1024];
    char decrypted[1024];
    const char* password = "secret123";

    while (true) {
        // ����� ������ �� �������
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0) {
            std::cout << "Client disconnected: " << clientIP << std::endl;
            break;
        }

        buffer[bytesReceived] = '\0';

        // ������������ ������
        crypt(buffer, decrypted, const_cast<char*>(password));

        std::cout << "Received encrypted: " << buffer << std::endl;
        std::cout << "Decrypted message: " << decrypted << std::endl;

        // ��������� ������� ������
        if (strcmp(decrypted, "quit") == 0) {
            std::cout << "Client requested disconnect: " << clientIP << std::endl;
            break;
        }

        // ���������� ������
        std::string response = "Server processed: " + std::string(decrypted);
        char encryptedResponse[1024];

        // ���������� ������
        crypt(const_cast<char*>(response.c_str()), encryptedResponse, const_cast<char*>(password));

        // �������� ������ �������
        send(clientSocket, encryptedResponse, strlen(encryptedResponse), 0);
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

    // �������� ������
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed." << std::endl;
        WSACleanup();
        return 1;
    }

    // ��������� ������ �������
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    // �������� ������
    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed." << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    // ������������� �����
    if (listen(serverSocket, 10) == SOCKET_ERROR) {
        std::cerr << "Listen failed." << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server is listening on port 12345..." << std::endl;
    std::cout << "Waiting for connections..." << std::endl;

    std::vector<SOCKET> clientSockets;

    while (true) {
        // �������� ����������
        sockaddr_in clientAddr;
        int clientSize = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientSize);

        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed." << std::endl;
            continue;
        }

        clientSockets.push_back(clientSocket);

        // ������ ��������� ������� (� ������ ������� ���������������)
        handleClient(clientSocket, clientAddr);
    }

    // �������� ���������� ������
    closesocket(serverSocket);
    WSACleanup();

    return 0;
}