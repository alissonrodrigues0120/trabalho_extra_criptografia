#include <iostream>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <chrono>
#include <random>
#include <iomanip>
#include <fstream>
#include <ctime>
#include <unordered_map>
#include <algorithm>

// Função para calcular hash SHAKE128
std::vector<unsigned char> shake128_hash(const std::string& input, size_t output_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* shake = EVP_shake128();
    
    std::vector<unsigned char> output(output_len);
    
    EVP_DigestInit_ex(ctx, shake, nullptr);
    EVP_DigestUpdate(ctx, input.c_str(), input.length());
    EVP_DigestFinalXOF(ctx, output.data(), output_len);
    
    EVP_MD_CTX_free(ctx);
    return output;
}

// Converter bytes para string hexadecimal
std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (unsigned char byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// Salvar resultado em arquivo
void save_result(const std::string& filename, const std::string& content) {
    std::ofstream file(filename);
    if (file.is_open()) {
        file << content;
        file.close();
        std::cout << "Resultado salvo em '" << filename << "'\n";
    } else {
        std::cout << "Nao foi possivel salvar o resultado em '" << filename << "'\n";
    }
}

// Gerar string aleatória com diferentes padrões
std::string generate_candidate(uint64_t attempts, std::mt19937_64& rng) {
    int pattern = rng() % 5;
    
    switch(pattern) {
        case 0: return "NUM-" + std::to_string(attempts);
        case 1: 
            {
                char chars[11];
                for (int i = 0; i < 10; i++) {
                    int r = rng() % 62;
                    chars[i] = (r < 10) ? '0' + r : (r < 36) ? 'A' + r - 10 : 'a' + r - 36;
                }
                chars[10] = '\0';
                return std::string("STR-") + chars;
            }
        case 2: return "TX-" + std::to_string(2025) + std::to_string((rng() % 1000000) + 100000);
        case 3: 
            {
                std::vector<std::string> prefixes = {"user", "client", "customer", "account", "student", "professor"};
                return prefixes[rng() % prefixes.size()] + std::to_string((rng() % 100000) + 10000);
            }
        case 4:
            {
                std::vector<std::string> categories = {"ELEC", "FASH", "HOME", "BOOK", "TOYS", "FOOD"};
                return categories[rng() % categories.size()] + "-" + 
                       std::to_string((rng() % 10000) + 1000) + "-" + 
                       std::to_string((rng() % 900) + 100);
            }
        default: return "DEFAULT-" + std::to_string(attempts);
    }
}

int main() {
    OpenSSL_add_all_digests();
    
    std::cout << "==========================================\n";
    std::cout << "    DESAFIO A - QUEBRA DE COLISAO\n";
    std::cout << "==========================================\n";
    std::cout << "Aluno: Álisson Rodrigues\n";
    std::cout << "Objetivo: Encontrar DUAS strings DIFERENTES com mesmo hash de 4 bytes\n";
    std::cout << "Tamanho do Hash: 4 bytes (32 bits)\n";
    std::cout << "Estrategia: Ataque do aniversario com tabela de hash\n";
    std::cout << "==========================================\n\n";
    
    auto start_time = std::chrono::high_resolution_clock::now();
    uint64_t attempts = 0;
    std::unordered_map<std::string, std::string> hash_table;
    
    std::mt19937_64 rng(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    
    std::string input1, input2;
    bool collision_found = false;
    
    std::cout << "Iniciando busca por colisao...\n";
    std::cout << "Dica: Esta busca geralmente leva menos de 1 minuto\n";
    std::cout << "==========================================\n\n";
    
    while (!collision_found) {
        attempts++;
        
        std::string candidate = generate_candidate(attempts, rng);
        
        // Calcular hash de 4 bytes
        auto hash_result = shake128_hash(candidate, 4);
        std::string hash_hex = bytes_to_hex(hash_result);
        
        // Verificar se este hash ja foi visto com uma string DIFERENTE
        if (hash_table.find(hash_hex) != hash_table.end()) {
            if (hash_table[hash_hex] != candidate) { // Garantir que as strings sejam diferentes
                input1 = hash_table[hash_hex];
                input2 = candidate;
                collision_found = true;
                break;
            }
        } else {
            hash_table[hash_hex] = candidate;
        }
        
        // Mostrar progresso a cada 10.000 tentativas
        if (attempts % 10000 == 0) {
            auto current_time = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time).count();
            double attempts_per_second = attempts / (duration / 1000.0);
            
            std::cout << "Tentativas: " << std::setw(8) << attempts 
                      << " | Hashes Unicos: " << std::setw(8) << hash_table.size()
                      << " | Vel: " << std::fixed << std::setprecision(2)
                      << attempts_per_second/1000.0 << " Kh/s\n";
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    double attempts_per_second = attempts / (duration / 1000.0);
    std::string final_hash = bytes_to_hex(shake128_hash(input1, 4));
    
    std::cout << "\n\n";
    std::cout << "==========================================\n";
    std::cout << "        [ COLISAO VALIDA ENCONTRADA! ]\n";
    std::cout << "==========================================\n";
    std::cout << "STRING 1: \"" << input1 << "\"\n";
    std::cout << "STRING 2: \"" << input2 << "\"\n";
    std::cout << "HASH COMUM (4 bytes): " << final_hash << "\n";
    std::cout << "[VERIFICACAO] As strings sao DIFERENTES: " 
              << (input1 != input2 ? "SIM ✓" : "NAO ✗") << "\n\n";
    std::cout << "Tentativas Totais: " << attempts << "\n";
    std::cout << "Hashes Unicos Armazenados: " << hash_table.size() << "\n";
    std::cout << "Tempo Total: " << duration/1000.0 << " segundos\n";
    std::cout << "Velocidade Media: " << std::fixed << std::setprecision(2)
              << attempts_per_second/1000.0 << " Kh/s\n";
    std::cout << "==========================================\n\n";
    
    // Salvar resultado
    std::stringstream result;
    result << "==========================================\n";
    result << "          RESULTADO DO DESAFIO A\n";
    result << "==========================================\n";
    result << "Aluno: Álisson Rodrigues\n\n";
    result << "STRING 1: \"" << input1 << "\"\n";
    result << "STRING 2: \"" << input2 << "\"\n";
    result << "HASH COMUM (4 bytes): " << final_hash << "\n";
    result << "VERIFICACAO: Strings DIFERENTES: " 
           << (input1 != input2 ? "SIM" : "NAO") << "\n\n";
    result << "Tentativas Totais: " << attempts << "\n";
    result << "Tempo Total: " << duration/1000.0 << " segundos\n";
    
    std::time_t now = std::time(nullptr);
    result << "Data/Hora: " << std::asctime(std::localtime(&now));
    result << "==========================================\n";
    
    save_result("desafio_a_result.txt", result.str());
    
    EVP_cleanup();
    return 0;
}
