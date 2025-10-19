#include <iostream>
#include <string>
#include <cstring>
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

int main() {
    std::cout << "=== TCP Client with Optional Encryption ===" << std::endl;

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
    if (serverIP.empty() || serverIP == "localhost") {
        serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    }
    else {
        serverAddr.sin_addr.s_addr = inet_addr(serverIP.c_str());
    }

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

    std::cin.ignore(); // Очистка буфера

    while (true) {
        // Ввод сообщения
        std::string message;
        std::cout << "Enter message: ";
        std::getline(std::cin, message);

        if (message == "quit") {
            // Отправляем команду выхода в зашифрованном виде для совместимости
            std::string encrypted_msg;
            char flag = 0x01; // Зашифровано
            encrypted_msg += flag;

            std::string temp_encrypted;
            crypt(message, temp_encrypted, password);
            encrypted_msg += temp_encrypted;

            send(clientSocket, encrypted_msg.c_str(), encrypted_msg.length(), 0);
            break;
        }

        // Выбор типа отправки
        std::string encryption_choice;
        std::cout << "Encrypt message? (y/n): ";
        std::getline(std::cin, encryption_choice);

        std::string final_message;

        if (encryption_choice == "y" || encryption_choice == "Y") {
            // Зашифрованное сообщение
            char flag = 0x01; // Первый бит = 1 - сообщение зашифровано
            final_message += flag;

            std::string encrypted_msg;
            crypt(message, encrypted_msg, password);
            final_message += encrypted_msg;

            std::cout << "Message encrypted and sent (" << message.length() << " characters)" << std::endl;
        }
        else {
            // Незашифрованное сообщение
            char flag = 0x00; // Первый бит = 0 - сообщение не зашифровано
            final_message += flag;
            final_message += message;

            std::cout << "Plain message sent (" << message.length() << " characters)" << std::endl;
        }

        // Отправка сообщения
        send(clientSocket, final_message.c_str(), final_message.length(), 0);

        // Прием ответа от сервера
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0) {
            std::cout << "Server disconnected." << std::endl;
            break;
        }

        buffer[bytesReceived] = '\0';

        // Проверяем флаг шифрования в ответе
        bool isEncrypted = (buffer[0] & 0x01) != 0;
        std::string received_response(buffer + 1, bytesReceived - 1);
        std::string decrypted_response;

        if (isEncrypted) {
            // Дешифрование ответа
            crypt(received_response, decrypted_response, password);
            std::cout << "Server response (encrypted): " << decrypted_response << std::endl;
        }
        else {
            // Ответ не зашифрован
            decrypted_response = received_response;
            std::cout << "Server response (plain): " << decrypted_response << std::endl;
        }
    }

    // Закрытие соединения
    std::cout << "Closing connection..." << std::endl;
    closesocket(clientSocket);
    WSACleanup();

    std::cout << "Client terminated." << std::endl;
    return 0;
}