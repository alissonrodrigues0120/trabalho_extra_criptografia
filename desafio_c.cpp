#include <iostream>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <chrono>
#include <thread>
#include <atomic>
#include <random>
#include <iomanip>
#include <mutex>
#include <fstream>
#include <ctime>
#include <cmath>

// Variáveis compartilhadas para threads
std::atomic<bool> found(false);
std::atomic<uint64_t> total_attempts(0);
std::string result_preimage;
std::mutex cout_mutex;

const std::string ALUNO_NOME = "Álisson Rodrigues";
const int NUM_THREADS = std::thread::hardware_concurrency();

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

// Converter bytes para string binária
std::string bytes_to_binary(const std::vector<unsigned char>& bytes, size_t num_bits) {
    std::string binary;
    for (unsigned char byte : bytes) {
        for (int i = 7; i >= 0; i--) {
            binary.push_back(((byte >> i) & 1) ? '1' : '0');
            if (binary.length() >= num_bits)
                return binary;
        }
    }
    return binary;
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

// Thread worker para busca paralela
void worker_thread(int thread_id, std::mt19937_64& rng) {
    uint64_t local_attempts = 0;
    const uint64_t report_interval = 500000; // Reportar a cada 500k tentativas
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // 34 bits do hash E82C07F0
    const std::string target_bits = "1110100000101100000001111111000000";
    
    while (!found) {
        local_attempts++;
        total_attempts++;
        
        // Gerar candidato aleatório com diferentes padrões
        std::string candidate;
        int pattern = rng() % 5;
        
        switch(pattern) {
            case 0: candidate = std::to_string(rng()); break; // Números puros
            case 1: candidate = "alisson" + std::to_string(rng() % 1000000); break; // Prefixo com letras
            case 2: candidate = std::to_string(rng() % 1000000) + "rodrigues"; break; // Sufixo com letras
            case 3: // Combinação alfanumérica curta
                {
                    char chars[9];
                    for (int i = 0; i < 8; i++) {
                        int r = rng() % 62;
                        chars[i] = (r < 10) ? '0' + r : (r < 36) ? 'A' + r - 10 : 'a' + r - 36;
                    }
                    chars[8] = '\0';
                    candidate = std::string(chars);
                }
                break;
            case 4: // Palavras comuns + números
                {
                    std::vector<std::string> words = {"senha", "security", "cripto", "hash", "aluno", "universidade", "computador", "sistema"};
                    candidate = words[rng() % words.size()] + std::to_string(rng() % 10000);
                }
                break;
        }
        
        // Calcular hash SHAKE128 com 5 bytes (40 bits)
        auto hash_result = shake128_hash(candidate, 5);
        std::string hash_bits = bytes_to_binary(hash_result, 34);
        
        // Verificar se os primeiros 34 bits correspondem ao alvo
        if (hash_bits == target_bits) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            if (!found) {
                found = true;
                result_preimage = candidate;
                
                auto end_time = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
                double attempts_per_second = total_attempts.load() / (duration / 1000.0);
                std::string full_hash_hex = bytes_to_hex(hash_result);
                
                std::cout << "\n\n";
                std::cout << "==========================================\n";
                std::cout << "        [ HASH #3 QUEBRADO! ]\n";
                std::cout << "==========================================\n";
                std::cout << "HASH ALVO: E82C07F0\n";
                std::cout << "PRE-IMAGEM ENCONTRADA: " << candidate << "\n";
                std::cout << "HASH COMPLETO (5 bytes): " << full_hash_hex << "\n";
                std::cout << "PRIMEIROS 34 BITS: " << hash_bits << "\n";
                std::cout << "TENTATIVAS TOTAIS: " << total_attempts.load() << "\n";
                std::cout << "TEMPO TOTAL: " << duration/1000.0 << " segundos\n";
                std::cout << "VELOCIDADE: " << std::fixed << std::setprecision(2) 
                          << attempts_per_second/1000000.0 << " Mhashes/segundo\n";
                std::cout << "==========================================\n\n";
                
                // Salvar resultado
                std::stringstream result;
                result << "==========================================\n";
                result << "          RESULTADO DO DESAFIO C\n";
                result << "==========================================\n";
                result << "Aluno: " << ALUNO_NOME << "\n";
                result << "Hash Alvo (#3): E82C07F0\n";
                result << "Pre-imagem Encontrada: " << candidate << "\n";
                result << "Hash Completo (5 bytes): " << full_hash_hex << "\n";
                result << "Primeiros 34 bits: " << hash_bits << "\n";
                result << "Tentativas Totais: " << total_attempts.load() << "\n";
                result << "Tempo Total: " << duration/1000.0 << " segundos\n";
                
                std::time_t now = std::time(nullptr);
                result << "Data/Hora: " << std::asctime(std::localtime(&now));
                result << "==========================================\n";
                
                save_result("hash3_result.txt", result.str());
                
                std::cout << "IMPORTANTE: INFORME IMEDIATAMENTE NO GRUPO DO TELEGRAM\n";
                std::cout << "Mensagem para enviar: \"Hash #3 (E82C07F0) quebrado por " << ALUNO_NOME << "\"\n";
                std::cout << "==========================================\n";
            }
            break;
        }
        
        // Reportar progresso periodicamente
        if (local_attempts % report_interval == 0 && !found) {
            auto current_time = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time).count();
            double attempts_per_second = total_attempts.load() / (duration / 1000.0);
            double progress_percent = (static_cast<double>(total_attempts.load()) / 17179869184.0) * 100.0;
            
            {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cout << "Thread " << std::setw(2) << thread_id << " | "
                          << "Hash #3 | "
                          << "Tentativas: " << std::setw(12) << total_attempts.load() << " | "
                          << "Vel: " << std::fixed << std::setprecision(2) 
                          << attempts_per_second/1000000.0 << " Mhash/s | "
                          << "Progresso: " << std::fixed << std::setprecision(4) 
                          << progress_percent << "%\n";
            }
        }
    }
}

int main() {
    OpenSSL_add_all_digests();
    
    std::cout << "==========================================\n";
    std::cout << "    DESAFIO C - QUEBRA DE PRE-IMAGEM\n";
    std::cout << "==========================================\n";
    std::cout << "Aluno: " << ALUNO_NOME << "\n";
    std::cout << "Hash Alvo #3: E82C07F0\n";
    std::cout << "Bits de Seguranca: 34 bits\n";
    std::cout << "Estrategia: Busca aleatoria paralela otimizada\n";
    std::cout << "Nucleos Detectados: " << NUM_THREADS << "\n";
    std::cout << "Estimativa: ~4-8 minutos em hardware moderno\n";
    std::cout << "==========================================\n\n";
    
    std::cout << "BitFields do Hash Alvo (34 bits):\n";
    std::cout << "11101000 00101100 00000111 11110000 00\n\n";
    
    std::cout << "Iniciando ataque paralelo...\n";
    std::cout << "DICA: Nao interrompa a execucao - o hash #3 pode ser quebrado por outros alunos!\n";
    std::cout << "==========================================\n\n";
    
    // Iniciar threads
    std::vector<std::thread> threads;
    std::vector<std::mt19937_64> rng_engines(NUM_THREADS);
    
    auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    for (int i = 0; i < NUM_THREADS; i++) {
        rng_engines[i].seed(seed + i * 1000000);
        threads.emplace_back(worker_thread, i, std::ref(rng_engines[i]));
    }
    
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
    
    if (!found) {
        std::cout << "\n\n";
        std::cout << "==========================================\n";
        std::cout << "        BUSCA CONCLUIDA SEM SUCESSO\n";
        std::cout << "==========================================\n";
        std::cout << "Tentativas realizadas: " << total_attempts.load() << "\n";
        std::cout << "Espaco de busca coberto: " 
                  << (static_cast<double>(total_attempts.load()) / 17179869184.0) * 100.0 << "%\n";
        std::cout << "Dica: Execute novamente - a busca e aleatoria!\n";
        std::cout << "==========================================\n";
    }
    
    EVP_cleanup();
    return 0;
}
