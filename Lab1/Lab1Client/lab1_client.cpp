#include <iostream>
#include <string>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

// ������� ��������� �����
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

// ������� ����������/������������
void crypt(const std::string& source, std::string& dest, const char* pwd) {
    dest.clear();
    unsigned int g = gamma(pwd);

    for (size_t i = 0; i < source.length(); i++) {
        // XOR-���������� ������� �������
        char encrypted_char = source[i] ^ (char)(g & 0xFF);
        dest += encrypted_char;

        // ����������� ����� �����
        g = (g >> 1) | (g << 31);
    }
}

int main() {
    std::cout << "=== TCP Client with Optional Encryption ===" << std::endl;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    // �������� ������
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed." << std::endl;
        WSACleanup();
        return 1;
    }

    // ������ ������ �������
    std::string serverIP;
    std::cout << "Enter server IP (127.0.0.1 for localhost): ";
    std::cin >> serverIP;

    // ��������� ������ �������
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345);
    if (serverIP.empty() || serverIP == "localhost") {
        serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    }
    else {
        serverAddr.sin_addr.s_addr = inet_addr(serverIP.c_str());
    }

    // ��������� ����������
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

    std::cin.ignore(); // ������� ������

    while (true) {
        // ���� ���������
        std::string message;
        std::cout << "Enter message: ";
        std::getline(std::cin, message);

        if (message == "quit") {
            // ���������� ������� ������ � ������������� ���� ��� �������������
            std::string encrypted_msg;
            char flag = 0x01; // �����������
            encrypted_msg += flag;

            std::string temp_encrypted;
            crypt(message, temp_encrypted, password);
            encrypted_msg += temp_encrypted;

            send(clientSocket, encrypted_msg.c_str(), encrypted_msg.length(), 0);
            break;
        }

        // ����� ���� ��������
        std::string encryption_choice;
        std::cout << "Encrypt message? (y/n): ";
        std::getline(std::cin, encryption_choice);

        std::string final_message;

        if (encryption_choice == "y" || encryption_choice == "Y") {
            // ������������� ���������
            char flag = 0x01; // ������ ��� = 1 - ��������� �����������
            final_message += flag;

            std::string encrypted_msg;
            crypt(message, encrypted_msg, password);
            final_message += encrypted_msg;

            std::cout << "Message encrypted and sent (" << message.length() << " characters)" << std::endl;
        }
        else {
            // ��������������� ���������
            char flag = 0x00; // ������ ��� = 0 - ��������� �� �����������
            final_message += flag;
            final_message += message;

            std::cout << "Plain message sent (" << message.length() << " characters)" << std::endl;
        }

        // �������� ���������
        send(clientSocket, final_message.c_str(), final_message.length(), 0);

        // ����� ������ �� �������
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0) {
            std::cout << "Server disconnected." << std::endl;
            break;
        }

        buffer[bytesReceived] = '\0';

        // ��������� ���� ���������� � ������
        bool isEncrypted = (buffer[0] & 0x01) != 0;
        std::string received_response(buffer + 1, bytesReceived - 1);
        std::string decrypted_response;

        if (isEncrypted) {
            // ������������ ������
            crypt(received_response, decrypted_response, password);
            std::cout << "Server response (encrypted): " << decrypted_response << std::endl;
        }
        else {
            // ����� �� ����������
            decrypted_response = received_response;
            std::cout << "Server response (plain): " << decrypted_response << std::endl;
        }
    }

    // �������� ����������
    std::cout << "Closing connection..." << std::endl;
    closesocket(clientSocket);
    WSACleanup();

    std::cout << "Client terminated." << std::endl;
    return 0;
}